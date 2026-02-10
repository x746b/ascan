#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
// Fallback definitions for musl/minimal libc environments
#ifdef __has_include
#  if __has_include(<linux/errqueue.h>)
#    include <linux/errqueue.h>
#  endif
#endif
#ifndef IP_RECVERR
#  define IP_RECVERR 11
#endif
#ifndef MSG_ERRQUEUE
#  define MSG_ERRQUEUE 0x2000
#endif
#include <stdatomic.h>
#include <ctype.h>
#include <netdb.h>
#include <strings.h>

static int g_threadLimit    = 100;
static int g_ctimeout       = 300; // msec
static int g_rechecks       = 0;
static int g_pingEnabled    = 1;
static int g_isPingOnly     = 0;
static int g_netbiosEnabled = 0;
static int g_udpEnabled    = 0;
static int g_udpDelay      = 100; // msec

static const char* DEFAULT_PORTS =
"20,21,22,23,25,53,65,66,69,80,88,110,111,135,139,143,194,389,443,"
"445,464,465,587,593,636,873,993,995,1194,1433,1494,1521,1540,1666,1801,"
"1812,1813,2049,2179,2222,2383,2598,3000,3128,3268,3269,3306,3333,3389,4444,"
"4848,5000,5044,5060,5061,5432,5555,5601,5631,5666,5671,5672,5693,5900,"
"5931,5938,5984,5985,5986,6160,6200,6379,6443,6600,6771,7001,7474,7687,"
"7777,7990,8000,8006,8080,8081,8082,8086,8088,8090,8091,8200,8443,8444,8500,"
"8529,8530,8531,8600,8888,8912,9000,9042,9080,9090,9092,9160,9200,9229,9300,9389,"
"9443,9515,9999,10000,10001,10011,10050,10051,11211,15672,17990,27015,27017,30033,47001";

static const char* DEFAULT_UDP_PORTS = "53,67,68,69,88,123,137,138,161,389,500,514,623,1194,1900,5353";

// ── UDP protocol-specific probes (credits: github.com/nullt3r/udpx) ──────────────────────

typedef struct {
    const uint8_t *data;
    int length;
    const char *name;
} UdpProbe;

typedef struct {
    int port;
    const char *service;
    const UdpProbe *probes;
    int probe_count;
} UdpPortProbes;

// --- Port 53: DNS ---
static const uint8_t PROBE_DNS_NS[] = {
    0xfc, 0x8e, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0x3d, 0x23, 0xc0, 0x0a,
    0xf9, 0xd2, 0xfb, 0x3a
};
static const uint8_t PROBE_DNS_A[] = {
    0x00, 0x00, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0x97, 0xe3, 0x96, 0x8d, 0x78, 0xd0,
    0xf3, 0x6a
};
static const uint8_t PROBE_DNS_VERSION[] = {
    0x9e, 0x40, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e,
    0x64, 0x00, 0x00, 0x10, 0x00, 0x03, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0xd0, 0x7a, 0x30,
    0xe4, 0xd8, 0x59, 0x2e, 0xa0
};
static const UdpProbe DNS_PROBES[] = {
    { PROBE_DNS_NS,      sizeof(PROBE_DNS_NS),      "DNS-NS" },
    { PROBE_DNS_A,       sizeof(PROBE_DNS_A),        "DNS-A" },
    { PROBE_DNS_VERSION, sizeof(PROBE_DNS_VERSION),  "DNS-VER" },
};

// --- Port 69: TFTP ---
static const uint8_t PROBE_TFTP_READ[] = {
    0x00, 0x01, 0x2f, 0x61, 0x00, 0x6e, 0x65, 0x74, 0x61, 0x73, 0x63, 0x69,
    0x69, 0x00
};
static const UdpProbe TFTP_PROBES[] = {
    { PROBE_TFTP_READ, sizeof(PROBE_TFTP_READ), "TFTP-RRQ" },
};

// --- Port 88: Kerberos ---
static const uint8_t PROBE_KERBEROS_ASREQ[] = {
    0x6a, 0x7a, 0x30, 0x78, 0xa1, 0x03, 0x02, 0x01, 0x05, 0xa2, 0x03, 0x02,
    0x01, 0x0a, 0xa4, 0x6c, 0x30, 0x6a, 0xa0, 0x07, 0x03, 0x05, 0x00, 0x40,
    0x00, 0x00, 0x00, 0xa1, 0x11, 0x30, 0x0f, 0xa0, 0x03, 0x02, 0x01, 0x01,
    0xa1, 0x08, 0x30, 0x06, 0x1b, 0x04, 0x6e, 0x6d, 0x61, 0x70, 0xa2, 0x06,
    0x1b, 0x04, 0x74, 0x65, 0x73, 0x74, 0xa3, 0x19, 0x30, 0x17, 0xa0, 0x03,
    0x02, 0x01, 0x02, 0xa1, 0x10, 0x30, 0x0e, 0x1b, 0x06, 0x6b, 0x72, 0x62,
    0x74, 0x67, 0x74, 0x1b, 0x04, 0x74, 0x65, 0x73, 0x74, 0xa5, 0x11, 0x18,
    0x0f, 0x32, 0x30, 0x32, 0x32, 0x31, 0x31, 0x31, 0x33, 0x32, 0x31, 0x34,
    0x35, 0x30, 0x32, 0x5a, 0xa7, 0x06, 0x02, 0x04, 0x09, 0x4a, 0x76, 0x81,
    0xa8, 0x0e, 0x30, 0x0c, 0x02, 0x01, 0x12, 0x02, 0x01, 0x11, 0x02, 0x01,
    0x10, 0x02, 0x01, 0x17
};
static const UdpProbe KERBEROS_PROBES[] = {
    { PROBE_KERBEROS_ASREQ, sizeof(PROBE_KERBEROS_ASREQ), "KRB-ASREQ" },
};

// --- Port 123: NTP ---
static const uint8_t PROBE_NTP_V4[] = {
    0xe3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xea, 0x95, 0xbd, 0x30, 0xb9, 0xc5, 0xa0, 0x00
};
static const uint8_t PROBE_NTP_V2[] = {
    0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const UdpProbe NTP_PROBES[] = {
    { PROBE_NTP_V4, sizeof(PROBE_NTP_V4), "NTPv4" },
    { PROBE_NTP_V2, sizeof(PROBE_NTP_V2), "NTPv2" },
};

// --- Port 137: NetBIOS ---
static const uint8_t PROBE_NETBIOS_STAT[] = {
    0xe5, 0xd8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
    0x00, 0x01
};
static const UdpProbe NETBIOS_PROBES[] = {
    { PROBE_NETBIOS_STAT, sizeof(PROBE_NETBIOS_STAT), "NBSTAT" },
};

// --- Port 161: SNMP ---
static const uint8_t PROBE_SNMP_V1[] = {
    0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
    0x63, 0xa0, 0x1c, 0x02, 0x04, 0x56, 0x5a, 0xdc, 0x5d, 0x02, 0x01, 0x00,
    0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01,
    0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00
};
static const uint8_t PROBE_SNMP_V2C[] = {
    0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
    0x63, 0xa1, 0x19, 0x02, 0x04, 0xdc, 0x63, 0xc2, 0x9a, 0x02, 0x01, 0x00,
    0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01,
    0x02, 0x01, 0x05, 0x00
};
static const uint8_t PROBE_SNMP_V3[] = {
    0x30, 0x3a, 0x02, 0x01, 0x03, 0x30, 0x0f, 0x02, 0x02, 0x4a, 0x69, 0x02,
    0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10,
    0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00,
    0x04, 0x00, 0x04, 0x00, 0x30, 0x12, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0c,
    0x02, 0x02, 0x37, 0xf0, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00
};
static const UdpProbe SNMP_PROBES[] = {
    { PROBE_SNMP_V1,  sizeof(PROBE_SNMP_V1),  "SNMPv1" },
    { PROBE_SNMP_V2C, sizeof(PROBE_SNMP_V2C), "SNMPv2c" },
    { PROBE_SNMP_V3,  sizeof(PROBE_SNMP_V3),  "SNMPv3" },
};

// --- Port 389: CLDAP ---
static const uint8_t PROBE_CLDAP_ROOTDSE[] = {
    0x30, 0x84, 0x00, 0x00, 0x00, 0x2d, 0x02, 0x01, 0x01, 0x63, 0x84, 0x00,
    0x00, 0x00, 0x24, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02,
    0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62,
    0x6a, 0x65, 0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x84, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0a
};
static const UdpProbe CLDAP_PROBES[] = {
    { PROBE_CLDAP_ROOTDSE, sizeof(PROBE_CLDAP_ROOTDSE), "CLDAP" },
};

// --- Port 500: IKE ---
static const uint8_t PROBE_IKE_GENERIC[] = {
    0x5b, 0x5e, 0x64, 0xc0, 0x3e, 0x99, 0xb5, 0x11, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x50, 0x00, 0x00, 0x01, 0x34, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x28, 0x01, 0x01, 0x00, 0x08,
    0x03, 0x00, 0x00, 0x24, 0x01, 0x01
};
static const uint8_t PROBE_IKE_MALFORMED[] = { 0x00 };
static const UdpProbe IKE_PROBES[] = {
    { PROBE_IKE_GENERIC,   sizeof(PROBE_IKE_GENERIC),   "IKE-SA" },
    { PROBE_IKE_MALFORMED, sizeof(PROBE_IKE_MALFORMED), "IKE-MAL" },
};

// --- Port 623: IPMI ---
static const uint8_t PROBE_IPMI_RMCP[] = {
    0x06, 0x00, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x09, 0x20, 0x18, 0xc8, 0x81, 0x00, 0x38, 0x8e, 0x04, 0xb5
};
static const UdpProbe IPMI_PROBES[] = {
    { PROBE_IPMI_RMCP, sizeof(PROBE_IPMI_RMCP), "RMCP" },
};

// --- Port 1194: OpenVPN ---
static const uint8_t PROBE_OPENVPN_RESET[] = {
    0x38, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x38, 0xb1, 0x26, 0xde
};
static const UdpProbe OPENVPN_PROBES[] = {
    { PROBE_OPENVPN_RESET, sizeof(PROBE_OPENVPN_RESET), "OVPN-RST" },
};

// --- Port 1900: UPnP/SSDP ---
static const uint8_t PROBE_UPNP_SEARCH[] = {
    0x4d, 0x2d, 0x53, 0x45, 0x41, 0x52, 0x43, 0x48, 0x20, 0x2a, 0x20, 0x48,
    0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x4f, 0x53,
    0x54, 0x3a, 0x32, 0x33, 0x39, 0x2e, 0x32, 0x35, 0x35, 0x2e, 0x32, 0x35,
    0x35, 0x2e, 0x32, 0x35, 0x30, 0x3a, 0x31, 0x39, 0x30, 0x30, 0x0d, 0x0a,
    0x53, 0x54, 0x3a, 0x73, 0x73, 0x64, 0x70, 0x3a, 0x61, 0x6c, 0x6c, 0x0d,
    0x0a, 0x4d, 0x41, 0x4e, 0x3a, 0x22, 0x73, 0x73, 0x64, 0x70, 0x3a, 0x64,
    0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x22, 0x0d, 0x0a, 0x0d, 0x0a
};
static const UdpProbe UPNP_PROBES[] = {
    { PROBE_UPNP_SEARCH, sizeof(PROBE_UPNP_SEARCH), "SSDP" },
};

// --- Port 5353: mDNS ---
static const uint8_t PROBE_MDNS_REVERSE[] = {
    0x1b, 0x6c, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x01, 0x31, 0x01, 0x30, 0x01, 0x30, 0x03, 0x31, 0x32, 0x37, 0x07, 0x69,
    0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00,
    0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0x7f, 0x01, 0xfa, 0x70, 0x0e,
    0x0c, 0x8e, 0xb0
};
static const UdpProbe MDNS_PROBES[] = {
    { PROBE_MDNS_REVERSE, sizeof(PROBE_MDNS_REVERSE), "mDNS" },
};

static const UdpPortProbes UDP_PROBE_TABLE[] = {
    {   53, "DNS",      DNS_PROBES,      3 },
    {   69, "TFTP",     TFTP_PROBES,     1 },
    {   88, "Kerberos", KERBEROS_PROBES, 1 },
    {  123, "NTP",      NTP_PROBES,      2 },
    {  137, "NetBIOS",  NETBIOS_PROBES,  1 },
    {  161, "SNMP",     SNMP_PROBES,     3 },
    {  389, "CLDAP",    CLDAP_PROBES,    1 },
    {  500, "IKE",      IKE_PROBES,      2 },
    {  623, "IPMI",     IPMI_PROBES,     1 },
    { 1194, "OpenVPN",  OPENVPN_PROBES,  1 },
    { 1900, "UPnP",     UPNP_PROBES,     1 },
    { 5353, "mDNS",     MDNS_PROBES,     1 },
};
#define UDP_PROBE_TABLE_SIZE (sizeof(UDP_PROBE_TABLE) / sizeof(UDP_PROBE_TABLE[0]))

static const UdpPortProbes *find_udp_probes(int port) {
    int lo = 0, hi = (int)UDP_PROBE_TABLE_SIZE - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (UDP_PROBE_TABLE[mid].port == port) return &UDP_PROBE_TABLE[mid];
        else if (UDP_PROBE_TABLE[mid].port < port) lo = mid + 1;
        else hi = mid - 1;
    }
    return NULL;
}

typedef struct {
    char ip[INET_ADDRSTRLEN];
    char netbiosName[NI_MAXHOST];
    char **details;
    int detailCount, detailCap;
    int *openPorts;
    int openCount, openCap;
    int *openUdpPorts;
    int openUdpCount, openUdpCap;
    atomic_int responded;
    pthread_mutex_t cs;
} IPResult;

static IPResult *g_ipResults = NULL;
static int g_ipCount = 0;
static int *g_ports = NULL;
static int g_portCount = 0;
static int *g_udpPorts = NULL;
static int g_udpPortCount = 0;
static atomic_int g_taskIndex;
static atomic_int g_pingProgress;
static atomic_int g_portProgress;
static atomic_int g_udpProgress;

static void print_header(void) {
    printf("\033[36m");
    printf(" _____     _   _____             \n");
    printf("|  _  |___| |_|   __|___ ___ ___ \n");
    printf("|     |  _|  _|__   |  _| .'|   |\n");
    printf("|__|__|_| |_| |_____|___|__,|_|_|\n");
    printf("\033[32mArtScan by @art3x (Linux)\033[0m\n");
    printf("\033[35mforked by xtk -> added UDP scan & unprivileged ICMP\033[0m\n");
    printf("\033[34mhttps://github.com/art3x\033[0m\n");
    printf("\033[34mhttps://github.com/x746b/ascan\033[0m\n\n");
}

static int cmp_int(const void *a, const void *b) {
    return (*(const int*)a - *(const int*)b);
}

static int is_http_like_port(int port) {
    switch (port) {
        case 80: case 443: case 8000: case 8008: case 8080: case 8081:
        case 8082: case 8086: case 8088: case 8090: case 8091: case 8443:
        case 8888: case 9000: case 9080: case 9090: case 9091: case 9092:
        case 9200: case 5601:
            return 1;
        default:
            return 0;
    }
}

static void summarize_http(const char *resp, char *out, size_t outsz) {
    out[0] = '\0';
    if (!resp || !out || outsz == 0) return;

    char statusLine[160] = {0};
    const char *p = strstr(resp, "HTTP/");
    if (p) {
        const char *lineEnd = strpbrk(p, "\r\n");
        size_t len = lineEnd ? (size_t)(lineEnd - p) : strlen(p);
        if (len >= sizeof(statusLine)) len = sizeof(statusLine) - 1;
        strncpy(statusLine, p, len);
        statusLine[len] = '\0';
    }

    char version[32] = {0};
    char reason[96] = {0};
    int statusCode = 0;
    if (statusLine[0]) {
        sscanf(statusLine, "%31s %d %95[^\r\n]", version, &statusCode, reason);
    }

    char title[160] = {0};
    const char *titleStart = strcasestr(resp, "<title");
    if (titleStart) {
        titleStart = strchr(titleStart, '>');
        if (titleStart) {
            titleStart++;
            const char *titleEnd = strcasestr(titleStart, "</title>");
            if (titleEnd && titleEnd > titleStart) {
                size_t len = (size_t)(titleEnd - titleStart);
                if (len >= sizeof(title)) len = sizeof(title) - 1;
                strncpy(title, titleStart, len);
                title[len] = '\0';
            }
        }
    }

    for (char *c = title; *c; c++) {
        if (*c == '\r' || *c == '\n' || *c == '\t') *c = ' ';
    }
    char *tstart = title;
    while (*tstart == ' ') tstart++;
    char *tend = tstart + strlen(tstart);
    while (tend > tstart && *(tend - 1) == ' ') { *(--tend) = '\0'; }
    if (strlen(tstart) > 192) tstart[192] = '\0';

    char statusColored[200] = {0};
    if (statusCode > 0) {
        const char *colorStart = "";
        if (statusCode >= 200 && statusCode < 300) colorStart = "\033[32m";
        else if (statusCode >= 300 && statusCode < 500) colorStart = "\033[33m";
        else if (statusCode >= 500 && statusCode < 600) colorStart = "\033[31m";
        const char *colorEnd = colorStart[0] ? "\033[0m" : "";
        if (version[0]) {
            snprintf(statusColored, sizeof(statusColored), "%s %s%d%s%s%s",
                     version, colorStart, statusCode, colorEnd,
                     reason[0] ? " " : "", reason);
        } else {
            snprintf(statusColored, sizeof(statusColored), "%s%d%s%s%s",
                     colorStart, statusCode, colorEnd,
                     reason[0] ? " " : "", reason);
        }
    } else if (statusLine[0]) {
        strncpy(statusColored, statusLine, sizeof(statusColored) - 1);
    }

    const char *titleColorStart = "\033[97m";
    const char *titleColorEnd = "\033[0m";
    if (statusColored[0] && tstart[0]) {
        snprintf(out, outsz, "%s | Title: %s%s%s", statusColored, titleColorStart, tstart, titleColorEnd);
    } else if (statusColored[0]) {
        snprintf(out, outsz, "%s", statusColored);
    } else if (tstart[0]) {
        snprintf(out, outsz, "Title: %s%s%s", titleColorStart, tstart, titleColorEnd);
    }
}

typedef struct {
    const char *label;
    atomic_int *counter;
    int total;
    atomic_int stopFlag;
} ProgressCtx;

static void *progress_worker(void *arg) {
    ProgressCtx *ctx = arg;
    int last = -1;
    while (!atomic_load(&ctx->stopFlag)) {
        int done = atomic_load(ctx->counter);
        if (done > ctx->total) done = ctx->total;
        if (done != last) {
            double pct = ctx->total ? (done * 100.0 / ctx->total) : 100.0;
            printf("\r[%s] %d/%d (%.1f%%)", ctx->label, done, ctx->total, pct);
            fflush(stdout);
            last = done;
        }
        usleep(100000);
    }
    int done = atomic_load(ctx->counter);
    if (done > ctx->total) done = ctx->total;
    double pct = ctx->total ? (done * 100.0 / ctx->total) : 100.0;
    printf("\r[%s] %d/%d (%.1f%%)\n", ctx->label, done, ctx->total, pct);
    fflush(stdout);
    return NULL;
}

static unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

static void add_detail(int idx, const char *msg) {
    IPResult *r = &g_ipResults[idx];
    pthread_mutex_lock(&r->cs);
    if (r->detailCount >= r->detailCap) {
        r->detailCap = r->detailCap ? r->detailCap * 2 : 4;
        r->details = realloc(r->details, r->detailCap * sizeof(char*));
    }
    r->details[r->detailCount++] = strdup(msg);
    pthread_mutex_unlock(&r->cs);
}

static void add_open(int idx, int port) {
    IPResult *r = &g_ipResults[idx];
    pthread_mutex_lock(&r->cs);
    if (r->openCount >= r->openCap) {
        r->openCap = r->openCap ? r->openCap * 2 : 4;
        r->openPorts = realloc(r->openPorts, r->openCap * sizeof(int));
    }
    r->openPorts[r->openCount++] = port;
    pthread_mutex_unlock(&r->cs);
}

static void add_open_udp(int idx, int port) {
    IPResult *r = &g_ipResults[idx];
    pthread_mutex_lock(&r->cs);
    if (r->openUdpCount >= r->openUdpCap) {
        r->openUdpCap = r->openUdpCap ? r->openUdpCap * 2 : 4;
        r->openUdpPorts = realloc(r->openUdpPorts, r->openUdpCap * sizeof(int));
    }
    r->openUdpPorts[r->openUdpCount++] = port;
    pthread_mutex_unlock(&r->cs);
}

static int parse_ports_into(const char *spec, int **out_ports, int *out_count) {
    if (!spec) return 0;
    if (!strcasecmp(spec, "all")) {
        *out_count = 65535;
        *out_ports = malloc(*out_count * sizeof(int));
        if (!*out_ports) return 0;
        for (int p = 0; p < *out_count; p++) (*out_ports)[p] = p + 1;
        return 1;
    }
    char *s = strdup(spec);
    char *tok = strtok(s, ",");
    int *tmp = malloc(65536 * sizeof(int));
    int cnt = 0;
    while (tok) {
        int a, b;
        if (sscanf(tok, "%d-%d", &a, &b) == 2) {
            if (a < 1 || b > 65535 || b < a) { free(s); free(tmp); return 0; }
            for (int p = a; p <= b; p++) tmp[cnt++] = p;
        } else {
            a = atoi(tok);
            if (a < 1 || a > 65535) { free(s); free(tmp); return 0; }
            tmp[cnt++] = a;
        }
        tok = strtok(NULL, ",");
    }
    free(s);
    if (cnt > 0) {
        *out_ports = malloc(cnt * sizeof(int));
        memcpy(*out_ports, tmp, cnt * sizeof(int));
    }
    *out_count = cnt;
    free(tmp);
    return 1;
}

static int parse_ports(const char *spec) {
    return parse_ports_into(spec, &g_ports, &g_portCount);
}

static int parse_udp_ports(const char *spec) {
    return parse_ports_into(spec, &g_udpPorts, &g_udpPortCount);
}

int resolve_hostname_to_ip(const char* hostname, char* ip_buffer, size_t buffer_len) {
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0) {
        return 0;
    }

    struct sockaddr_in* ipv4 = (struct sockaddr_in*)result->ai_addr;
    if (inet_ntop(AF_INET, &ipv4->sin_addr, ip_buffer, buffer_len) == NULL) {
        freeaddrinfo(result);
        return 0;
    }

    freeaddrinfo(result);
    return 1;
}

int parse_ip_range_spec(const char *spec, char *startIp, char* endIp) {
    const char *dash = strchr(spec, '-');
    if (!dash) return 0;

    size_t len = dash - spec;
    if (len >= INET_ADDRSTRLEN) return 0;
    memcpy(startIp, spec, len); startIp[len] = '\0';

    if (!strchr(dash + 1, '.')) {
        char tmp[INET_ADDRSTRLEN];
        strncpy(tmp, startIp, sizeof(tmp)-1);
        tmp[sizeof(tmp)-1] = '\0';
        char *lastDot = strrchr(tmp, '.');
        if (!lastDot) return 0;
        *(lastDot + 1) = '\0';
        snprintf(endIp, INET_ADDRSTRLEN, "%s%s", tmp, dash + 1);
    } else {
        snprintf(endIp, INET_ADDRSTRLEN, "%s", dash + 1);
    }
    return 1;
}

int setup_ip_targets(const char *startIp, const char *endIp) {
    struct in_addr ia, ib;
    if (inet_pton(AF_INET, startIp, &ia) != 1) return 0;
    if (inet_pton(AF_INET, endIp, &ib) != 1) return 0;
    uint32_t s = ntohl(ia.s_addr), e = ntohl(ib.s_addr);
    if (e < s) return 0;
    g_ipCount = e - s + 1;
    g_ipResults = calloc(g_ipCount, sizeof(IPResult));
    if (!g_ipResults) return 0;
    for (int i = 0; i < g_ipCount; i++) {
        uint32_t ipn = htonl(s + i);
        inet_ntop(AF_INET, &ipn, g_ipResults[i].ip, sizeof(g_ipResults[i].ip));
        g_ipResults[i].netbiosName[0] = '\0';
        pthread_mutex_init(&g_ipResults[i].cs, NULL);
        atomic_init(&g_ipResults[i].responded, 0);
    }
    return 1;
}

enum { ICMP_PACKET_SIZE = sizeof(struct icmphdr) + 32 };

static void *worker_ping(void *_) {
    // SOCK_DGRAM = unprivileged ICMP (Linux 3.0+), kernel manages ID + checksum
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) { return NULL; }
    struct timeval tv = { g_ctimeout / 1000, (g_ctimeout % 1000) * 1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char pkt[ICMP_PACKET_SIZE];
    struct icmphdr *hdr = (struct icmphdr*)pkt;

    while (1) {
        int idx = atomic_fetch_add(&g_taskIndex, 1);
        if (idx >= g_ipCount) break;

        memset(pkt, 0, ICMP_PACKET_SIZE);
        hdr->type = ICMP_ECHO;
        hdr->code = 0;
        hdr->un.echo.id = 0;
        hdr->un.echo.sequence = htons(idx & 0xFFFF);

        struct sockaddr_in dst = { .sin_family = AF_INET };
        inet_pton(AF_INET, g_ipResults[idx].ip, &dst.sin_addr);
        sendto(sock, pkt, ICMP_PACKET_SIZE, 0, (struct sockaddr*)&dst, sizeof(dst));

        char buf[1500];
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        while (1) {
            int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&peer, &plen);
            if (n <= 0) break;

            if ((size_t)n < sizeof(struct icmphdr)) continue;
            struct icmphdr *icm = (struct icmphdr*)buf;
            if (icm->type == ICMP_ECHOREPLY && icm->un.echo.sequence == hdr->un.echo.sequence) {
                atomic_store(&g_ipResults[idx].responded, 1);

                if (g_netbiosEnabled) {
                    char host[NI_MAXHOST] = {0};
                    if (getnameinfo((struct sockaddr*)&peer, plen, host, sizeof(host), NULL, 0, 0) == 0) {
                        pthread_mutex_lock(&g_ipResults[idx].cs);
                        strncpy(g_ipResults[idx].netbiosName, host, sizeof(g_ipResults[idx].netbiosName) - 1);
                        pthread_mutex_unlock(&g_ipResults[idx].cs);
                    }
                }

                if (g_isPingOnly) {
                    char m[NI_MAXHOST + 100];
                    pthread_mutex_lock(&g_ipResults[idx].cs);
                    if (g_ipResults[idx].netbiosName[0]) {
                        snprintf(m, sizeof(m), "%s (%s) responded to ping", g_ipResults[idx].ip, g_ipResults[idx].netbiosName);
                    } else {
                        snprintf(m, sizeof(m), "%s responded to ping", g_ipResults[idx].ip);
                    }
                    pthread_mutex_unlock(&g_ipResults[idx].cs);
                    add_detail(idx, m);
                    add_open(idx, 0);
                }
                break;
            }
        }
        atomic_fetch_add(&g_pingProgress, 1);
    }
    close(sock);
    return NULL;
}


static void *worker_port(void *_) {
    int total = g_ipCount * g_portCount;
    while (1) {
        int t = atomic_fetch_add(&g_taskIndex, 1);
        if (t >= total) break;

        int idx  = t / g_portCount;
        int port = g_ports[t % g_portCount];
        if (g_pingEnabled && !atomic_load(&g_ipResults[idx].responded)) { atomic_fetch_add(&g_portProgress, 1); continue; }

        char banner[512];
        char msg[1024];
        int open_success = 0;
        char httpInfo[256] = {0};

        for (int attempt = 0; attempt <= g_rechecks; attempt++) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;

            fcntl(sock, F_SETFL, O_NONBLOCK);
            struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
            inet_pton(AF_INET, g_ipResults[idx].ip, &sa.sin_addr);
            connect(sock, (void*)&sa, sizeof(sa));

            fd_set wf; FD_ZERO(&wf); FD_SET(sock, &wf);
            struct timeval tvc = {g_ctimeout / 1000, (g_ctimeout % 1000) * 1000};

            if (select(sock + 1, NULL, &wf, NULL, &tvc) > 0) {
                int err = 0; socklen_t el = sizeof(err);
                if (!getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &el) && err == 0) {
                    struct timeval rto = {g_ctimeout / 1000, (g_ctimeout % 1000) * 1000};
                    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto));
                    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) & ~O_NONBLOCK);

                    if (is_http_like_port(port)) {
                        char req[256];
                        snprintf(req, sizeof(req),
                                 "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: ascan\r\nConnection: close\r\n\r\n",
                                 g_ipResults[idx].ip);
                        send(sock, req, strlen(req), 0);
                        char resp[2048];
                        int total = 0;
                        while (total < (int)sizeof(resp) - 1) {
                            int n = recv(sock, resp + total, sizeof(resp) - 1 - total, 0);
                            if (n <= 0) break;
                            total += n;
                            if (strstr(resp, "\r\n\r\n")) break;
                        }
                        resp[total] = '\0';
                        summarize_http(resp, httpInfo, sizeof(httpInfo));
                    }

                    if (!httpInfo[0]) {
                        memset(banner, 0, sizeof(banner));
                        int n = recv(sock, banner, sizeof(banner) - 1, 0);
                        if (n > 0) { banner[n] = '\0'; char *p = strpbrk(banner, "\r\n"); if (p) *p = '\0'; }
                    }

                    if (httpInfo[0]) {
                        snprintf(msg, sizeof(msg), "%s:%d \033[32mopen\033[0m. %s", g_ipResults[idx].ip, port, httpInfo);
                    } else if (banner[0]) {
                        snprintf(msg, sizeof(msg), "%s:%d \033[32mopen\033[0m %s", g_ipResults[idx].ip, port, banner);
                    } else {
                        snprintf(msg, sizeof(msg), "%s:%d \033[32mopen\033[0m", g_ipResults[idx].ip, port);
                    }
                    add_open(idx, port);
                    add_detail(idx, msg);
                    open_success = 1;
                }
            }
            close(sock);
            if (open_success) break;
        }
        atomic_fetch_add(&g_portProgress, 1);
    }
    return NULL;
}

static void *worker_port_udp(void *_) {
    int total = g_ipCount * g_udpPortCount;
    while (1) {
        int t = atomic_fetch_add(&g_taskIndex, 1);
        if (t >= total) break;

        int idx  = t / g_udpPortCount;
        int port = g_udpPorts[t % g_udpPortCount];
        if (g_pingEnabled && !atomic_load(&g_ipResults[idx].responded)) {
            atomic_fetch_add(&g_udpProgress, 1);
            continue;
        }

        char msg[1024];
        int is_confirmed_open = 0;
        int is_open_filtered = 0;
        int is_closed = 0;

        const UdpPortProbes *pp = find_udp_probes(port);

        const uint8_t null_probe[1] = {0};
        const UdpProbe fallback = { null_probe, 1, NULL };
        int num_probes = pp ? pp->probe_count : 1;

        for (int pi = 0; pi < num_probes && !is_confirmed_open && !is_closed; pi++) {
            const UdpProbe *probe = pp ? &pp->probes[pi] : &fallback;

            if (pi > 0) usleep(100000);

            for (int attempt = 0; attempt <= g_rechecks && !is_confirmed_open && !is_closed; attempt++) {
                int sock = socket(AF_INET, SOCK_DGRAM, 0);
                if (sock < 0) continue;

                int one = 1;
                setsockopt(sock, IPPROTO_IP, IP_RECVERR, &one, sizeof(one));

                struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(port)};
                inet_pton(AF_INET, g_ipResults[idx].ip, &sa.sin_addr);

                if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
                    close(sock);
                    continue;
                }

                if (send(sock, probe->data, probe->length, 0) < 0) {
                    if (errno == ECONNREFUSED) { is_closed = 1; }
                    close(sock);
                    continue;
                }

                fd_set rfds, efds;
                FD_ZERO(&rfds); FD_SET(sock, &rfds);
                FD_ZERO(&efds); FD_SET(sock, &efds);
                struct timeval tv = {0, g_ctimeout * 1000};

                int sel = select(sock + 1, &rfds, NULL, &efds, &tv);

                if (sel > 0) {
                    char errbuf[512];
                    struct iovec iov = { errbuf, sizeof(errbuf) };
                    char control[256];
                    struct msghdr msgh = {0};
                    msgh.msg_iov = &iov;
                    msgh.msg_iovlen = 1;
                    msgh.msg_control = control;
                    msgh.msg_controllen = sizeof(control);

                    int ret = recvmsg(sock, &msgh, MSG_ERRQUEUE | MSG_DONTWAIT);
                    if (ret >= 0) {
                        is_closed = 1;
                    } else if (FD_ISSET(sock, &rfds)) {
                        char buf[512];
                        int n = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
                        if (n > 0) {
                            is_confirmed_open = 1;
                        } else if (n < 0 && errno == ECONNREFUSED) {
                            is_closed = 1;
                        } else {
                            is_open_filtered = 1;
                        }
                    }
                } else if (sel == 0) {
                    is_open_filtered = 1;
                }

                close(sock);
            }
        }

        if (is_confirmed_open) {
            if (pp)
                snprintf(msg, sizeof(msg), "%s:%d/udp \033[32mopen\033[0m %s", g_ipResults[idx].ip, port, pp->service);
            else
                snprintf(msg, sizeof(msg), "%s:%d/udp \033[32mopen\033[0m", g_ipResults[idx].ip, port);
            add_open_udp(idx, port);
            add_detail(idx, msg);
        } else if (is_open_filtered && !is_closed) {
            snprintf(msg, sizeof(msg), "%s:%d/udp \033[36mopen|filtered\033[0m", g_ipResults[idx].ip, port);
            add_open_udp(idx, port);
            add_detail(idx, msg);
        }

        atomic_fetch_add(&g_udpProgress, 1);
        if (g_udpDelay > 0) usleep(g_udpDelay * 1000);
    }
    return NULL;
}

int main(int argc, char **argv) {
    char *targetSpec = NULL;
    char *portSpec = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-T") && i + 1 < argc) g_threadLimit = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t") && i + 1 < argc) g_ctimeout = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-r") && i + 1 < argc) g_rechecks = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-Pn")) g_pingEnabled = 0;
        else if (!strcmp(argv[i], "-i")) g_isPingOnly = 1;
        else if (!strcmp(argv[i], "-Nb")) g_netbiosEnabled = 1;
        else if (!strcmp(argv[i], "-sU")) g_udpEnabled = 1;
        else if (!strcmp(argv[i], "-d") && i + 1 < argc) g_udpDelay = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-h")) {
            printf("Usage: %s <target> [ports] [options]\n", argv[0]);
            printf("  target:    Hostname (e.g., scanme.nmap.org), single IP, or range (192.168.1.1-100)\n");
            printf("  ports:     Single port, range (80-90), comma-separated list (22,80,443), or 'all'\n");
            printf("Options:\n");
            printf("  -T <num>:  Set thread limit (default: %d)\n", 100);
            printf("  -t <ms>:   Set port scan timeout in msec (default: %d)\n", 300);
            printf("  -r <num>:  Set extra rechecks for unanswered ports (default: %d)\n", 0);
            printf("  -Pn:       Disable ping (skip host discovery)\n");
            printf("  -i:        Perform icmp scan only (skip port scan)\n");
            printf("  -sU:       Enable UDP scan (uses TOP 16 UDP ports if no ports specified)\n");
            printf("  -d <ms>:   Set delay between UDP ports in msec (default: %d)\n", 100);
            printf("  -Nb:       Enable hostname resolution via reverse DNS lookup\n");
            printf("  -h:        Display this help message\n");
            printf("\nUDP Scanning Notes:\n");
            printf("  Default UDP ports: 53,67,68,69,88,123,137,138,161,389,500,514,623,1194,1900,5353\n");
            printf("  Protocol-specific probes for: DNS, TFTP, Kerberos, NTP, NetBIOS, SNMP, CLDAP,\n");
            printf("    IKE, IPMI, OpenVPN, UPnP, mDNS (ports without probes use null-byte fallback)\n");
            printf("  UDP scanning is slower due to ICMP rate limiting on targets\n");
            return 0;
        } else if (argv[i][0] == '-') { fprintf(stderr, "Unknown option: %s\n", argv[i]); return 1; }
        else {
            if (!targetSpec) targetSpec = argv[i];
            else if (!portSpec) portSpec = argv[i];
        }
    }

    print_header();

    if (!targetSpec) { fprintf(stderr, "Error: Target required. Use -h for help.\n"); return 1; }
    if (!portSpec && !g_isPingOnly) portSpec = (char*)DEFAULT_PORTS;

    char *udpPortSpec = portSpec;
    int udpUsingDefault = 0;
    if (g_udpEnabled && portSpec == DEFAULT_PORTS) {
        udpPortSpec = (char*)DEFAULT_UDP_PORTS;
        udpUsingDefault = 1;
    }

    char startIp[INET_ADDRSTRLEN], endIp[INET_ADDRSTRLEN];
    if (parse_ip_range_spec(targetSpec, startIp, endIp)) {
        // range
    } else {
        if (!resolve_hostname_to_ip(targetSpec, startIp, sizeof(startIp))) {
            struct in_addr addr_test;
            if (inet_pton(AF_INET, targetSpec, &addr_test) != 1) {
                fprintf(stderr, "\033[31mError: Could not resolve '%s' and it is not a valid IP.\n\033[0m", targetSpec);
                return 1;
            }
            strncpy(startIp, targetSpec, sizeof(startIp));
        }
        strncpy(endIp, startIp, sizeof(endIp));
    }

    printf("\033[97m");
    printf("[.] Scanning Target: %s\n", targetSpec);
    if (!g_isPingOnly) {
        printf("[.] TCP ports: %s\n", portSpec == DEFAULT_PORTS ? "TOP 123" : portSpec);
        if (g_udpEnabled) {
            printf("[.] UDP ports: %s\n", udpUsingDefault ? "TOP 16 (53,67,68,69,88,123,137,138,161,389,500,514,623,1194,1900,5353)" : udpPortSpec);
        }
    } else {
        printf("[.] Ping-only scan mode\n");
    }
    printf("[.] Threads: %d   Rechecks: %d   Timeout: %d ms", g_threadLimit, g_rechecks, g_ctimeout);
    if (g_udpEnabled) printf("   UDP delay: %d ms", g_udpDelay);
    printf("\n");
    if (!g_pingEnabled) printf("[.] Ping disabled (-Pn flag used)\n");
    printf("\033[0m\n");

    struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
    if (!setup_ip_targets(startIp, endIp)) { fprintf(stderr, "Invalid IP range setup.\n"); return 1; }
    if (!g_isPingOnly && !parse_ports(portSpec)) { fprintf(stderr, "Invalid port specification.\n"); return 1; }
    if (g_udpEnabled && !parse_udp_ports(udpPortSpec)) { fprintf(stderr, "Invalid UDP port specification.\n"); return 1; }
    atomic_init(&g_pingProgress, 0);
    atomic_init(&g_portProgress, 0);
    atomic_init(&g_udpProgress, 0);

    pthread_t *threads = malloc(sizeof(pthread_t) * g_threadLimit);
    if (g_pingEnabled) {
        ProgressCtx pingCtx = {.label = "Ping", .counter = &g_pingProgress, .total = g_ipCount};
        atomic_init(&pingCtx.stopFlag, 0);
        pthread_t pingProgThread;
        int usePingProgress = g_ipCount > 0;
        atomic_init(&g_taskIndex, 0);
        if (usePingProgress) pthread_create(&pingProgThread, NULL, progress_worker, &pingCtx);
        for (int i = 0; i < g_threadLimit; i++) pthread_create(&threads[i], NULL, worker_ping, NULL);
        for (int i = 0; i < g_threadLimit; i++) pthread_join(threads[i], NULL);
        if (usePingProgress) { atomic_store(&pingCtx.stopFlag, 1); pthread_join(pingProgThread, NULL); }
    } else {
        for(int i=0; i<g_ipCount; i++) atomic_store(&g_ipResults[i].responded, 1);
    }

    if (!g_isPingOnly) {
        long totalPorts = (long)g_ipCount * (long)g_portCount;
        ProgressCtx portCtx = {.label = "TCP", .counter = &g_portProgress, .total = (int)totalPorts};
        atomic_init(&portCtx.stopFlag, 0);
        pthread_t portProgThread;
        int usePortProgress = totalPorts > 0;
        atomic_init(&g_taskIndex, 0);
        if (usePortProgress) pthread_create(&portProgThread, NULL, progress_worker, &portCtx);
        for (int i = 0; i < g_threadLimit; i++) pthread_create(&threads[i], NULL, worker_port, NULL);
        for (int i = 0; i < g_threadLimit; i++) pthread_join(threads[i], NULL);
        if (usePortProgress) { atomic_store(&portCtx.stopFlag, 1); pthread_join(portProgThread, NULL); }

        if (g_udpEnabled && g_udpPortCount > 0) {
            int udpThreads = 1;
            long totalUdpPorts = (long)g_ipCount * (long)g_udpPortCount;
            ProgressCtx udpCtx = {.label = "UDP", .counter = &g_udpProgress, .total = (int)totalUdpPorts};
            atomic_init(&udpCtx.stopFlag, 0);
            pthread_t udpProgThread;
            int useUdpProgress = totalUdpPorts > 0;
            atomic_init(&g_taskIndex, 0);
            if (useUdpProgress) pthread_create(&udpProgThread, NULL, progress_worker, &udpCtx);
            for (int i = 0; i < udpThreads; i++) pthread_create(&threads[i], NULL, worker_port_udp, NULL);
            for (int i = 0; i < udpThreads; i++) pthread_join(threads[i], NULL);
            if (useUdpProgress) { atomic_store(&udpCtx.stopFlag, 1); pthread_join(udpProgThread, NULL); }
        }
        printf("\n");
    }
    free(threads);

    clock_gettime(CLOCK_MONOTONIC,&t1);
    double elapsed=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;

    int first_output = 1;
    for (int i = 0; i < g_ipCount; i++) {
        if (g_ipResults[i].detailCount > 0) {
            if (!first_output) printf("\033[97m------------------\033[0m\n");
            for (int j = 0; j < g_ipResults[i].detailCount; j++) printf("%s\n", g_ipResults[i].details[j]);
            first_output = 0;
        }
    }

    printf("\033[33m\nSummary:\n\033[0m");
    for (int i = 0; i < g_ipCount; i++) {
        IPResult *r = &g_ipResults[i];
        if (r->openCount > 0 || r->openUdpCount > 0) {
            if (g_isPingOnly) {
                if (r->netbiosName[0]) printf("%s (%s) responded to ping\n", r->ip, r->netbiosName);
                else printf("%s responded to ping\n", r->ip);
            } else {
                if (r->netbiosName[0]) printf("%s (%s): ", r->ip, r->netbiosName);
                else printf("%s: ", r->ip);

                if (r->openCount > 0) {
                    qsort(r->openPorts, r->openCount, sizeof(int), cmp_int);
                    printf("TCP ");
                    for (int j = 0; j < r->openCount; j++) printf("%d%s", r->openPorts[j], j < r->openCount - 1 ? "," : "");
                }

                if (r->openUdpCount > 0) {
                    if (r->openCount > 0) printf(" | ");
                    qsort(r->openUdpPorts, r->openUdpCount, sizeof(int), cmp_int);
                    printf("UDP ");
                    for (int j = 0; j < r->openUdpCount; j++) printf("%d%s", r->openUdpPorts[j], j < r->openUdpCount - 1 ? "," : "");
                }
                printf("\n");
            }
        }
    }
    
    printf("\nScan Duration: %.2f s\n",elapsed);
    
    if (g_ports) free(g_ports);
    if (g_udpPorts) free(g_udpPorts);
    for (int i = 0; i < g_ipCount; i++) {
        for (int j = 0; j < g_ipResults[i].detailCount; j++) free(g_ipResults[i].details[j]);
        free(g_ipResults[i].details);
        free(g_ipResults[i].openPorts);
        free(g_ipResults[i].openUdpPorts);
        pthread_mutex_destroy(&g_ipResults[i].cs);
    }
    free(g_ipResults);

    return 0;
}
