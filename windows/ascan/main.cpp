#include "pch.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>

// Fallback definition for SIO_UDP_CONNRESET (may not be defined in older SDKs)
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>  // for _beginthreadex
#include <stdio.h>    // for snprintf, sscanf
#include <ctype.h>    // for isdigit()

#include "output.h"
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

int main(int argc, char* argv[]);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow) {
    return main(__argc, __argv);
}

Output* output = NULL;

#define G_THREAD_LIMIT 20
#define G_TIMEOUT_DEFAULT 300
#define G_RECHECKS 0
int g_threadLimit = G_THREAD_LIMIT;
static int g_ctimeout = G_TIMEOUT_DEFAULT;
int g_rechecks = G_RECHECKS;

bool g_supportsANSI = false;

static int g_pingEnabled = 1;
static int g_isPingOnly = 0;

static int g_netbiosEnabled = 0;

static int g_udpEnabled = 0;
static int g_udpDelay = 100;
static int* g_udpPorts = NULL;
static int g_udpPortCount = 0;
static LONG g_udpProgress = 0;

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

static LONG g_pingProgress = 0;
static LONG g_portProgress = 0;
static bool g_headerPrintedStdout = false;

typedef struct _IPResult {
    char ip[INET_ADDRSTRLEN];
    char netbiosName[256];
    char** details;
    int detailCount;
    int detailCapacity;
    int* openPorts;
    int openCount;
    int openCapacity;
    int* openUdpPorts;
    int openUdpCount;
    int openUdpCapacity;
    CRITICAL_SECTION cs;
    int responded;
} IPResult;

static IPResult* g_ipResults = NULL;
static int g_ipCount = 0;  // Number of IPs in the range

static void print_header_stdout() {
    if (g_supportsANSI) printf("\033[36m");
    printf(" _____     _   _____             \n");
    printf("|  _  |___| |_|   __|___ ___ ___ \n");
    printf("|     |  _|  _|__   |  _| .'|   |\n");
    printf("|__|__|_| |_| |_____|___|__,|_|_|\n");
    if (g_supportsANSI) printf("\033[32m");
    printf("ArtScan by @art3x (Windows)\n");
    if (g_supportsANSI) printf("\033[35m");
    printf("forked by xtk -> added UDP scan\n");
    if (g_supportsANSI) printf("\033[34m");
    printf("https://github.com/art3x\n");
    if (g_supportsANSI) printf("\033[0m");
    printf("\n");
}


static void cleanup_ip_results() {
    if (!g_ipResults) {
        return;
    }

    for (int i = 0; i < g_ipCount; i++) {
        IPResult* ipRes = &g_ipResults[i];
        DeleteCriticalSection(&ipRes->cs);
        for (int j = 0; j < ipRes->detailCount; j++) {
            free(ipRes->details[j]);
        }
        free(ipRes->details);
        free(ipRes->openPorts);
        free(ipRes->openUdpPorts);
    }

    free(g_ipResults);
    g_ipResults = NULL;
    g_ipCount = 0;
}

void initConsoleColorSupport() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            if (dwMode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) {
                g_supportsANSI = true;
            }
        }
    }
}


void add_ip_result(int ipIndex, int port, const char* message) {
    if (ipIndex < 0 || ipIndex >= g_ipCount)
        return;
    IPResult* ipRes = &g_ipResults[ipIndex];
    EnterCriticalSection(&ipRes->cs);
    if (ipRes->detailCount >= ipRes->detailCapacity) {
        int newCapacity = (ipRes->detailCapacity == 0) ? 4 : ipRes->detailCapacity * 2;
        char** newDetails = (char**)realloc(ipRes->details, newCapacity * sizeof(char*));
        if (!newDetails) {
            LeaveCriticalSection(&ipRes->cs);
            return;
        }
        ipRes->details = newDetails;
        ipRes->detailCapacity = newCapacity;
    }
    ipRes->details[ipRes->detailCount] = _strdup(message);
    ipRes->detailCount++;

    if (ipRes->openCount >= ipRes->openCapacity) {
        int newCapacity = (ipRes->openCapacity == 0) ? 4 : ipRes->openCapacity * 2;
        int* newPorts = (int*)realloc(ipRes->openPorts, newCapacity * sizeof(int));
        if (!newPorts) {
            LeaveCriticalSection(&ipRes->cs);
            return;
        }
        ipRes->openPorts = newPorts;
        ipRes->openCapacity = newCapacity;
    }
    ipRes->openPorts[ipRes->openCount++] = port;
    LeaveCriticalSection(&ipRes->cs);
}

void add_udp_result(int ipIndex, int port, const char* message) {
    if (ipIndex < 0 || ipIndex >= g_ipCount)
        return;
    IPResult* ipRes = &g_ipResults[ipIndex];
    EnterCriticalSection(&ipRes->cs);
    if (ipRes->detailCount >= ipRes->detailCapacity) {
        int newCapacity = (ipRes->detailCapacity == 0) ? 4 : ipRes->detailCapacity * 2;
        char** newDetails = (char**)realloc(ipRes->details, newCapacity * sizeof(char*));
        if (!newDetails) {
            LeaveCriticalSection(&ipRes->cs);
            return;
        }
        ipRes->details = newDetails;
        ipRes->detailCapacity = newCapacity;
    }
    ipRes->details[ipRes->detailCount] = _strdup(message);
    ipRes->detailCount++;

    if (ipRes->openUdpCount >= ipRes->openUdpCapacity) {
        int newCapacity = (ipRes->openUdpCapacity == 0) ? 4 : ipRes->openUdpCapacity * 2;
        int* newPorts = (int*)realloc(ipRes->openUdpPorts, newCapacity * sizeof(int));
        if (!newPorts) {
            LeaveCriticalSection(&ipRes->cs);
            return;
        }
        ipRes->openUdpPorts = newPorts;
        ipRes->openUdpCapacity = newCapacity;
    }
    ipRes->openUdpPorts[ipRes->openUdpCount++] = port;
    LeaveCriticalSection(&ipRes->cs);
}

int cmp_int(const void* a, const void* b) {
    int int_a = *(const int*)a;
    int int_b = *(const int*)b;
    return int_a - int_b;
}

static const char* strcasestr_local(const char* haystack, const char* needle) {
    if (!haystack || !needle || !*needle) return haystack;
    size_t nlen = strlen(needle);
    for (const char* p = haystack; *p; p++) {
        if (_strnicmp(p, needle, nlen) == 0) return p;
    }
    return NULL;
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

static void summarize_http(const char* resp, char* out, size_t outsz) {
    if (!out || outsz == 0) return;
    out[0] = '\0';
    if (!resp) return;

    char statusLine[160] = { 0 };
    const char* p = strstr(resp, "HTTP/");
    if (p) {
        const char* lineEnd = strpbrk(p, "\r\n");
        size_t len = lineEnd ? (size_t)(lineEnd - p) : strlen(p);
        if (len >= sizeof(statusLine)) len = sizeof(statusLine) - 1;
        strncpy(statusLine, p, len);
        statusLine[len] = '\0';
    }

    char version[32] = { 0 };
    char reason[96] = { 0 };
    int statusCode = 0;
    if (statusLine[0]) {
        sscanf_s(statusLine, "%31s %d %95[^\r\n]", version, (unsigned)_countof(version), &statusCode, reason, (unsigned)_countof(reason));
    }

    char title[256] = { 0 };
    const char* titleStart = strcasestr_local(resp, "<title");
    if (titleStart) {
        titleStart = strchr(titleStart, '>');
        if (titleStart) {
            titleStart++;
            const char* titleEnd = strcasestr_local(titleStart, "</title>");
            if (titleEnd && titleEnd > titleStart) {
                size_t len = (size_t)(titleEnd - titleStart);
                if (len >= sizeof(title)) len = sizeof(title) - 1;
                strncpy(title, titleStart, len);
                title[len] = '\0';
            }
        }
    }

    for (char* c = title; *c; c++) {
        if (*c == '\r' || *c == '\n' || *c == '\t') *c = ' ';
    }
    char* tstart = title;
    while (*tstart == ' ') tstart++;
    char* tend = tstart + strlen(tstart);
    while (tend > tstart && *(tend - 1) == ' ') { *(--tend) = '\0'; }
    if (strlen(tstart) > 192) tstart[192] = '\0';

    char statusColored[200] = { 0 };
    if (statusCode > 0) {
        const char* colorStart = "\033[0m";
        if (statusCode >= 200 && statusCode < 300) colorStart = "\033[32m";
        else if (statusCode >= 300 && statusCode < 500) colorStart = "\033[33m";
        else if (statusCode >= 500 && statusCode < 600) colorStart = "\033[31m";
        const char* colorEnd = "\033[0m";
        if (version[0]) {
            snprintf(statusColored, sizeof(statusColored), "%s %s%d%s%s%s",
                version, colorStart, statusCode, colorEnd,
                reason[0] ? " " : "", reason);
        }
        else {
            snprintf(statusColored, sizeof(statusColored), "%s%d%s%s%s",
                colorStart, statusCode, colorEnd,
                reason[0] ? " " : "", reason);
        }
    }
    else if (statusLine[0]) {
        strncpy(statusColored, statusLine, sizeof(statusColored) - 1);
    }

    const char* titleColorStart = g_supportsANSI ? "\033[97m" : "";
    const char* titleColorEnd = g_supportsANSI ? "\033[0m" : "";
    if (statusCode >= 200 && statusCode < 300 && tstart[0]) {
        snprintf(out, outsz, "%s | Title: %s%s%s", statusColored, titleColorStart, tstart, titleColorEnd);
    }
    else if (statusColored[0]) {
        snprintf(out, outsz, "%s", statusColored);
    }
    else if (tstart[0]) {
        snprintf(out, outsz, "Title: %s%s%s", titleColorStart, tstart, titleColorEnd);
    }
}

typedef struct {
    const char* label;
    volatile LONG* counter;
    int total;
    volatile LONG stopFlag;
} ProgressCtx;

unsigned __stdcall progress_thread(void* param) {
    ProgressCtx* ctx = (ProgressCtx*)param;
    int last = -1;
    while (!ctx->stopFlag) {
        int done = (int)InterlockedCompareExchange((volatile LONG*)ctx->counter, 0, 0);
        if (done > ctx->total) done = ctx->total;
        if (done != last) {
            double pct = ctx->total ? (done * 100.0 / ctx->total) : 100.0;
            printf("\r[%s] %d/%d (%.1f%%)", ctx->label, done, ctx->total, pct);
            fflush(stdout);
            last = done;
        }
        Sleep(100);
    }
    int done = (int)InterlockedCompareExchange((volatile LONG*)ctx->counter, 0, 0);
    if (done > ctx->total) done = ctx->total;
    double pct = ctx->total ? (done * 100.0 / ctx->total) : 100.0;
    printf("\r[%s] %d/%d (%.1f%%)\n", ctx->label, done, ctx->total, pct);
    fflush(stdout);
    return 0;
}


#define ICMP_ECHO_DATA "abcdefghijklmnopqrstuvwabdcefghi"
#define ICMP_REPLY_SIZE (sizeof(ICMP_ECHO_REPLY) + sizeof(ICMP_ECHO_DATA))
#define ICMP_TIMEOUT_DEFAULT 1800

DWORD ping_ip(HANDLE hIcmpFile, IPAddr ip, PICMP_ECHO_REPLY reply) {
    IP_OPTION_INFORMATION options = { 0 };
    options.Ttl = 128;
    return IcmpSendEcho2(
        hIcmpFile,
        NULL,
        NULL,
        NULL,
        ip,
        (LPVOID)ICMP_ECHO_DATA,
        sizeof(ICMP_ECHO_DATA) - 1,
        &options,
        reply,
        ICMP_REPLY_SIZE,
        ICMP_TIMEOUT_DEFAULT
    );
}

typedef struct _PingThreadData {
    char ip[INET_ADDRSTRLEN];
    int ipIndex;
} PingThreadData;

unsigned __stdcall ping_thread(void* param) {
    PingThreadData* data = (PingThreadData*)param;
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) {
        free(data);
        return 0;
    }
    struct in_addr addr;
    if (inet_pton(AF_INET, data->ip, &addr) != 1) {
        free(data);
        IcmpCloseHandle(hIcmp);
        return 0;
    }
    IPAddr ipAddr = addr.s_addr;
    char replyBuffer[ICMP_REPLY_SIZE];
    PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)replyBuffer;
    DWORD dwRetVal = ping_ip(hIcmp, ipAddr, reply);
    if (dwRetVal != 0 && reply->Status == IP_SUCCESS) {
        InterlockedExchange((volatile LONG*)&g_ipResults[data->ipIndex].responded, 1);

        if (g_netbiosEnabled) {
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_addr = addr;
            char host[NI_MAXHOST] = { 0 };
            int res = getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, 0);
            if (res == 0) {
                EnterCriticalSection(&g_ipResults[data->ipIndex].cs);
                strncpy(g_ipResults[data->ipIndex].netbiosName, host, sizeof(g_ipResults[data->ipIndex].netbiosName) - 1);
                g_ipResults[data->ipIndex].netbiosName[sizeof(g_ipResults[data->ipIndex].netbiosName) - 1] = '\0';
                LeaveCriticalSection(&g_ipResults[data->ipIndex].cs);
            }
        }
        if (g_isPingOnly) {
            char message[256];
            if (g_ipResults[data->ipIndex].netbiosName[0] != '\0')
                snprintf(message, sizeof(message), "%s (%s) responded to ping", data->ip, g_ipResults[data->ipIndex].netbiosName);
            else
                snprintf(message, sizeof(message), "%s responded to ping", data->ip);
            add_ip_result(data->ipIndex, 0, message);
        }
    }
    IcmpCloseHandle(hIcmp);
    free(data);
    InterlockedIncrement(&g_pingProgress);
    return 0;
}

int parse_ports(const char* input, int** ports, int* count) {
    if (!input || !ports || !count) return 0;
    if (_stricmp(input, "all") == 0) {
        int* arr = (int*)malloc(sizeof(int) * 65535);
        if (!arr) return 0;
        for (int i = 0; i < 65535; i++) arr[i] = i + 1;
        *ports = arr;
        *count = 65535;
        return 1;
    }
    if (strchr(input, ',') != NULL) {
        char* copy = _strdup(input);
        if (!copy) return 0;
        int tokenCount = 0;
        char* token = strtok(copy, ",");
        while (token) {
            tokenCount++;
            token = strtok(NULL, ",");
        }
        free(copy);
        int* arr = (int*)malloc(sizeof(int) * tokenCount);
        if (!arr) return 0;
        copy = _strdup(input);
        if (!copy) { free(arr); return 0; }
        int idx = 0;
        token = strtok(copy, ",");
        while (token) {
            char* endptr;
            long port = strtol(token, &endptr, 10);
            if (port <= 0 || port > 65535) {
                free(copy);
                free(arr);
                return 0;
            }
            arr[idx++] = (int)port;
            token = strtok(NULL, ",");
        }
        free(copy);
        *ports = arr;
        *count = tokenCount;
        return 1;
    }
    else {
        const char* p = input;
        char* endptr;
        long first = strtol(p, &endptr, 10);
        if (first <= 0 || first > 65535) return 0;
        while (*endptr && !isdigit((unsigned char)*endptr) && *endptr != '-') {
            endptr++;
        }
        if (*endptr == '-') {
            const char* dashPos = endptr + 1;
            if (!isdigit((unsigned char)*dashPos)) {
                int* arr = (int*)malloc(sizeof(int));
                if (!arr) return 0;
                arr[0] = (int)first;
                *ports = arr;
                *count = 1;
                return 1;
            }
            else {
                long second = strtol(dashPos, &endptr, 10);
                if (second <= 0 || second > 65535 || second < first)
                    return 0;
                int cnt = (int)(second - first + 1);
                int* arr = (int*)malloc(sizeof(int) * cnt);
                if (!arr) return 0;
                for (int i = 0; i < cnt; i++) {
                    arr[i] = (int)first + i;
                }
                *ports = arr;
                *count = cnt;
                return 1;
            }
        }
        else {
            int* arr = (int*)malloc(sizeof(int));
            if (!arr) return 0;
            arr[0] = (int)first;
            *ports = arr;
            *count = 1;
            return 1;
        }
    }
}

int parse_ip_range(const char* input, char* startIp, char* endIp) {
    const char* dash = strchr(input, '-');
    if (!dash) {
        strncpy(startIp, input, INET_ADDRSTRLEN);
        startIp[INET_ADDRSTRLEN - 1] = '\0';
        strncpy(endIp, input, INET_ADDRSTRLEN);
        endIp[INET_ADDRSTRLEN - 1] = '\0';
    }
    else {
        size_t len = dash - input;
        if (len >= INET_ADDRSTRLEN)
            return 0;
        strncpy(startIp, input, len);
        startIp[len] = '\0';
        if (strchr(dash + 1, '.') == NULL) {
            strncpy(endIp, startIp, INET_ADDRSTRLEN);
            endIp[INET_ADDRSTRLEN - 1] = '\0';
            char* lastDot = strrchr(endIp, '.');
            if (!lastDot)
                return 0;
            size_t remain = INET_ADDRSTRLEN - (lastDot - endIp + 1);
            snprintf(lastDot + 1, remain, "%s", dash + 1);
        }
        else {
            strncpy(endIp, dash + 1, INET_ADDRSTRLEN);
            endIp[INET_ADDRSTRLEN - 1] = '\0';
        }
    }
    return 1;
}

uint32_t ip_to_int(const char* ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1)
        return 0;
    return ntohl(addr.s_addr);
}

void int_to_ip(uint32_t ipInt, char* buffer) {
    struct in_addr addr;
    addr.s_addr = htonl(ipInt);
    inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN);
}

int resolve_hostname_to_ip(const char* hostname, char* ip_buffer, size_t buffer_len) {
    struct addrinfo hints, * result;
    int status;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    status = getaddrinfo(hostname, NULL, &hints, &result);
    if (status != 0) {
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

typedef struct _ThreadData {
    char ip[INET_ADDRSTRLEN];
    int port;
    int ipIndex;
} ThreadData;

int scan_port(const char* ip, int port, int ipIndex) {
    int totalAttempts = 1 + g_rechecks;
    int attempt;
    int success = 0;
    char message[1024] = { 0 };

    for (attempt = 0; attempt < totalAttempts; attempt++) {
        SOCKET sock;
        struct sockaddr_in server;
        char buffer[1024];
        int result;
        int ctimeout = g_ctimeout;
        fd_set writefds;
        struct timeval tv;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
            continue;

        DWORD timeout = (DWORD)(ctimeout > 0 ? ctimeout : 100);
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);

        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        inet_pton(AF_INET, ip, &server.sin_addr);

        if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                FD_ZERO(&writefds);
                FD_SET(sock, &writefds);
                tv.tv_sec = ctimeout / 1000;
                tv.tv_usec = (ctimeout % 1000) * 1000;
                int res = select(0, NULL, &writefds, NULL, &tv);
                if (!(res > 0 && FD_ISSET(sock, &writefds))) {
                    closesocket(sock);
                    continue;
                }
                int err = 0; int errlen = sizeof(err);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &errlen) != 0 || err != 0) {
                    closesocket(sock);
                    continue;
                }
            }
            else {
                closesocket(sock);
                continue;
            }
        }

        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);

        char httpInfo[256] = { 0 };
        memset(buffer, 0, sizeof(buffer));

        if (is_http_like_port(port)) {
            char httpRequest[256];
            snprintf(httpRequest, sizeof(httpRequest),
                "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: ascan\r\nConnection: close\r\n\r\n",
                ip);
            send(sock, httpRequest, (int)strlen(httpRequest), 0);
            char httpResponse[2048];
            int totalReceived = 0;
            while (totalReceived < (int)sizeof(httpResponse) - 1) {
                int recvResult = recv(sock, httpResponse + totalReceived, sizeof(httpResponse) - totalReceived - 1, 0);
                if (recvResult <= 0) break;
                totalReceived += recvResult;
            }
            httpResponse[totalReceived] = '\0';
            summarize_http(httpResponse, httpInfo, sizeof(httpInfo));
        }

        if (!httpInfo[0]) {
            result = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (result > 0) {
                buffer[result] = '\0';
                char* newline = strpbrk(buffer, "\r\n");
                if (newline) *newline = '\0';
                if (strncmp(buffer, "HTTP/", 5) == 0) {
                    summarize_http(buffer, httpInfo, sizeof(httpInfo));
                }
            }
        }

        const char* greenStart = g_supportsANSI ? "\033[32m" : "";
        const char* greenEnd = g_supportsANSI ? "\033[0m" : "";
        if (httpInfo[0]) {
            snprintf(message, sizeof(message), "%s:%d %sopen%s. %s", ip, port, greenStart, greenEnd, httpInfo);
        }
        else if (buffer[0]) {
            snprintf(message, sizeof(message), "%s:%d %sopen%s %s", ip, port, greenStart, greenEnd, buffer);
        }
        else {
            snprintf(message, sizeof(message), "%s:%d %sopen%s", ip, port, greenStart, greenEnd);
        }
        success = 1;
        closesocket(sock);
        add_ip_result(ipIndex, port, message);
        break;
    }
    return success;
}

unsigned __stdcall port_thread(void* param) {
    ThreadData* data = (ThreadData*)param;
    scan_port(data->ip, data->port, data->ipIndex);
    free(data);
    InterlockedIncrement(&g_portProgress);
    return 0;
}

int scan_udp_port(const char* ip, int port, int ipIndex) {
    int totalAttempts = 1 + g_rechecks;
    int is_confirmed_open = 0;
    int is_open_filtered = 0;
    int is_closed = 0;
    char message[1024] = { 0 };

    const UdpPortProbes *pp = find_udp_probes(port);
    const uint8_t null_probe[1] = {0};
    const UdpProbe fallback = { null_probe, 1, NULL };
    int num_probes = pp ? pp->probe_count : 1;

    for (int pi = 0; pi < num_probes && !is_confirmed_open && !is_closed; pi++) {
        const UdpProbe *probe = pp ? &pp->probes[pi] : &fallback;

        if (pi > 0) Sleep(100);

        for (int attempt = 0; attempt < totalAttempts && !is_confirmed_open && !is_closed; attempt++) {
            SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (sock == INVALID_SOCKET)
                continue;

            BOOL bNewBehavior = TRUE;
            DWORD dwBytesReturned = 0;
            WSAIoctl(sock, SIO_UDP_CONNRESET, &bNewBehavior, sizeof(bNewBehavior),
                     NULL, 0, &dwBytesReturned, NULL, NULL);

            struct sockaddr_in server;
            memset(&server, 0, sizeof(server));
            server.sin_family = AF_INET;
            server.sin_port = htons(port);
            inet_pton(AF_INET, ip, &server.sin_addr);

            if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
                closesocket(sock);
                continue;
            }

            if (send(sock, (const char*)probe->data, probe->length, 0) == SOCKET_ERROR) {
                int err = WSAGetLastError();
                if (err == WSAECONNRESET) {
                    is_closed = 1;
                    closesocket(sock);
                    continue;
                }
            }

            Sleep(g_ctimeout);

            if (send(sock, (const char*)probe->data, probe->length, 0) == SOCKET_ERROR) {
                int err = WSAGetLastError();
                if (err == WSAECONNRESET) {
                    is_closed = 1;
                    closesocket(sock);
                    continue;
                }
            }

            DWORD timeout = 100;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

            char buf[512];
            int n = recv(sock, buf, sizeof(buf), 0);
            if (n > 0) {
                is_confirmed_open = 1;
            }
            else if (n == SOCKET_ERROR) {
                int err = WSAGetLastError();
                if (err == WSAECONNRESET) {
                    is_closed = 1;
                }
                else if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
                    is_open_filtered = 1;
                }
                else {
                    is_open_filtered = 1;
                }
            }

            closesocket(sock);
        }
    }

    if (is_confirmed_open) {
        const char* greenStart = g_supportsANSI ? "\033[32m" : "";
        const char* greenEnd = g_supportsANSI ? "\033[0m" : "";
        if (pp)
            snprintf(message, sizeof(message), "%s:%d/udp %sopen%s %s", ip, port, greenStart, greenEnd, pp->service);
        else
            snprintf(message, sizeof(message), "%s:%d/udp %sopen%s", ip, port, greenStart, greenEnd);
        add_udp_result(ipIndex, port, message);
        return 1;
    }
    else if (is_open_filtered && !is_closed) {
        const char* cyanStart = g_supportsANSI ? "\033[36m" : "";
        const char* cyanEnd = g_supportsANSI ? "\033[0m" : "";
        snprintf(message, sizeof(message), "%s:%d/udp %sopen|filtered%s", ip, port, cyanStart, cyanEnd);
        add_udp_result(ipIndex, port, message);
        return 1;
    }
    return 0;
}

unsigned __stdcall udp_port_thread(void* param) {
    ThreadData* data = (ThreadData*)param;
    scan_udp_port(data->ip, data->port, data->ipIndex);
    free(data);
    InterlockedIncrement(&g_udpProgress);
    return 0;
}

int run_port_scan(const char* targetSpec, const char* portRange) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        append(output, "WSAStartup failed\n");
        return -1;
    }
    g_pingProgress = 0;
    g_portProgress = 0;
    g_udpProgress = 0;

    DWORD startTime = GetTickCount();

    char startIp[INET_ADDRSTRLEN], endIp[INET_ADDRSTRLEN];

    if (strchr(targetSpec, '-') != NULL) {
        if (!parse_ip_range(targetSpec, startIp, endIp)) {
            append(output, "Invalid IP range format: %s\n", targetSpec);
            WSACleanup();
            return -1;
        }
    }
    else {
        if (resolve_hostname_to_ip(targetSpec, startIp, sizeof(startIp))) {
            strncpy(endIp, startIp, INET_ADDRSTRLEN);
            append(output, "[+] Resolved %s -> %s\n", targetSpec, startIp);
        }
        else {
            struct in_addr addr_test;
            if (inet_pton(AF_INET, targetSpec, &addr_test) == 1) {
                strncpy(startIp, targetSpec, INET_ADDRSTRLEN);
                strncpy(endIp, targetSpec, INET_ADDRSTRLEN);
            }
            else {
                append(output, "Error: Could not resolve hostname '%s' and it is not a valid IP or IP range.\n", targetSpec);
                WSACleanup();
                return -1;
            }
        }
    }

    int* portList = NULL;
    int portCount = 0;
    if (!g_isPingOnly) {
        if (!parse_ports(portRange, &portList, &portCount)) {
            append(output, "Invalid port specification\n");
            WSACleanup();
            return -1;
        }
    }

    int isRangeScan = (strcmp(startIp, endIp) != 0);
    uint32_t ipStart = ip_to_int(startIp);
    uint32_t ipEnd = ip_to_int(endIp);
    if (ipStart == 0 || ipEnd == 0) {
        append(output, "IP conversion failed\n");
        WSACleanup();
        if (portList) free(portList);
        return -1;
    }

    g_ipCount = (int)(ipEnd - ipStart + 1);
    g_ipResults = (IPResult*)malloc(sizeof(IPResult) * g_ipCount);
    if (!g_ipResults) {
        append(output, "Memory allocation failed for IP results\n");
        WSACleanup();
        if (portList) free(portList);
        return -1;
    }
    for (uint32_t i = 0; i < (uint32_t)g_ipCount; i++) {
        IPResult* ipRes = &g_ipResults[i];
        int_to_ip(ipStart + i, ipRes->ip);
        ipRes->netbiosName[0] = '\0';
        ipRes->details = NULL;
        ipRes->detailCount = 0;
        ipRes->detailCapacity = 0;
        ipRes->openPorts = NULL;
        ipRes->openCount = 0;
        ipRes->openCapacity = 0;
        ipRes->openUdpPorts = NULL;
        ipRes->openUdpCount = 0;
        ipRes->openUdpCapacity = 0;
        ipRes->responded = 0;
        InitializeCriticalSection(&ipRes->cs);
    }

    if (g_pingEnabled) {
        ProgressCtx pingCtx = { "Ping", &g_pingProgress, g_ipCount, 0 };
        HANDLE pingProgHandle = NULL;
        if (g_ipCount > 0) {
            pingProgHandle = (HANDLE)_beginthreadex(NULL, 0, progress_thread, &pingCtx, 0, NULL);
        }

        int pingThreadCount = 0;
        int pingThreadCapacity = g_threadLimit;
        HANDLE* pingHandles = (HANDLE*)malloc(sizeof(HANDLE) * pingThreadCapacity);
        if (!pingHandles) {
            append(output, "Memory allocation failed for ping handles\n");
            WSACleanup();
            cleanup_ip_results();
            if (portList) free(portList);
            return -1;
        }
        for (uint32_t ip = ipStart; ip <= ipEnd; ip++) {
            char ipStr[INET_ADDRSTRLEN];
            int_to_ip(ip, ipStr);
            int ipIndex = (int)(ip - ipStart);

            PingThreadData* data = (PingThreadData*)malloc(sizeof(PingThreadData));
            if (!data)
                continue;
            strncpy(data->ip, ipStr, INET_ADDRSTRLEN);
            data->ip[INET_ADDRSTRLEN - 1] = '\0';
            data->ipIndex = ipIndex;

            uintptr_t hThread = _beginthreadex(NULL, 0, ping_thread, data, 0, NULL);
            if (hThread != 0) {
                if (pingThreadCount >= pingThreadCapacity) {
                    WaitForMultipleObjects(pingThreadCount, pingHandles, TRUE, INFINITE);
                    for (int i = 0; i < pingThreadCount; i++)
                        CloseHandle(pingHandles[i]);
                    pingThreadCount = 0;
                }
                pingHandles[pingThreadCount++] = (HANDLE)hThread;
            }
            else {
                free(data);
            }
        }
        if (pingThreadCount > 0) {
            WaitForMultipleObjects(pingThreadCount, pingHandles, TRUE, INFINITE);
            for (int i = 0; i < pingThreadCount; i++) {
                CloseHandle(pingHandles[i]);
            }
        }
        free(pingHandles);
        if (pingProgHandle) {
            pingCtx.stopFlag = 1;
            WaitForSingleObject(pingProgHandle, INFINITE);
            CloseHandle(pingProgHandle);
        }
    }

    if (g_isPingOnly) {
        WSACleanup();
    }
    else {
        long portTaskTotal = 0;
        for (uint32_t ip = ipStart; ip <= ipEnd; ip++) {
            int ipIndex = (int)(ip - ipStart);
            if (g_pingEnabled && !g_ipResults[ipIndex].responded) continue;
            portTaskTotal += portCount;
        }

        ProgressCtx portCtx = { "TCP", &g_portProgress, (int)portTaskTotal, 0 };
        HANDLE portProgHandle = NULL;
        if (portTaskTotal > 0) {
            portProgHandle = (HANDLE)_beginthreadex(NULL, 0, progress_thread, &portCtx, 0, NULL);
        }

        int threadCount = 0;
        int capacity = g_threadLimit;
        HANDLE* handles = (HANDLE*)malloc(sizeof(HANDLE) * capacity);
        if (!handles) {
            append(output, "Memory allocation failed for port scan handles\n");
            WSACleanup();
            cleanup_ip_results();
            if (portList) free(portList);
            return -1;
        }
        for (uint32_t ip = ipStart; ip <= ipEnd; ip++) {
            char ipStr[INET_ADDRSTRLEN];
            int_to_ip(ip, ipStr);
            int ipIndex = (int)(ip - ipStart);

            if (g_pingEnabled && !g_ipResults[ipIndex].responded)
                continue;

            for (int i = 0; i < portCount; i++) {
                int port = portList[i];
                ThreadData* data = (ThreadData*)malloc(sizeof(ThreadData));
                if (!data)
                    continue;
                strncpy(data->ip, ipStr, INET_ADDRSTRLEN);
                data->ip[INET_ADDRSTRLEN - 1] = '\0';
                data->port = port;
                data->ipIndex = ipIndex;
                uintptr_t hThread = _beginthreadex(NULL, 0, port_thread, data, 0, NULL);
                if (hThread != 0) {
                    if (threadCount >= capacity) {
                        WaitForMultipleObjects(threadCount, handles, TRUE, INFINITE);
                        for (int i = 0; i < threadCount; i++)
                            CloseHandle(handles[i]);
                        threadCount = 0;
                    }
                    handles[threadCount++] = (HANDLE)hThread;
                }
                else {
                    free(data);
                }
            }
        }
        if (threadCount > 0) {
            WaitForMultipleObjects(threadCount, handles, TRUE, INFINITE);
            for (int i = 0; i < threadCount; i++) {
                CloseHandle(handles[i]);
            }
        }
        free(handles);
        if (portProgHandle) {
            portCtx.stopFlag = 1;
            WaitForSingleObject(portProgHandle, INFINITE);
            CloseHandle(portProgHandle);
        }

        if (g_udpEnabled && g_udpPortCount > 0) {
            long udpTaskTotal = 0;
            for (uint32_t ip = ipStart; ip <= ipEnd; ip++) {
                int ipIndex = (int)(ip - ipStart);
                if (g_pingEnabled && !g_ipResults[ipIndex].responded) continue;
                udpTaskTotal += g_udpPortCount;
            }

            ProgressCtx udpCtx = { "UDP", &g_udpProgress, (int)udpTaskTotal, 0 };
            HANDLE udpProgHandle = NULL;
            if (udpTaskTotal > 0) {
                udpProgHandle = (HANDLE)_beginthreadex(NULL, 0, progress_thread, &udpCtx, 0, NULL);
            }

            int udpThreadCount = 0;
            int udpCapacity = 1;
            HANDLE* udpHandles = (HANDLE*)malloc(sizeof(HANDLE) * udpCapacity);
            if (udpHandles) {
                for (uint32_t ip = ipStart; ip <= ipEnd; ip++) {
                    char ipStr[INET_ADDRSTRLEN];
                    int_to_ip(ip, ipStr);
                    int ipIndex = (int)(ip - ipStart);

                    if (g_pingEnabled && !g_ipResults[ipIndex].responded)
                        continue;

                    for (int i = 0; i < g_udpPortCount; i++) {
                        int port = g_udpPorts[i];
                        ThreadData* data = (ThreadData*)malloc(sizeof(ThreadData));
                        if (!data)
                            continue;
                        strncpy(data->ip, ipStr, INET_ADDRSTRLEN);
                        data->ip[INET_ADDRSTRLEN - 1] = '\0';
                        data->port = port;
                        data->ipIndex = ipIndex;
                        uintptr_t hThread = _beginthreadex(NULL, 0, udp_port_thread, data, 0, NULL);
                        if (hThread != 0) {
                            if (udpThreadCount >= udpCapacity) {
                                WaitForMultipleObjects(udpThreadCount, udpHandles, TRUE, INFINITE);
                                for (int j = 0; j < udpThreadCount; j++)
                                    CloseHandle(udpHandles[j]);
                                udpThreadCount = 0;
                                Sleep(g_udpDelay);
                            }
                            udpHandles[udpThreadCount++] = (HANDLE)hThread;
                        }
                        else {
                            free(data);
                        }
                    }
                }
                if (udpThreadCount > 0) {
                    WaitForMultipleObjects(udpThreadCount, udpHandles, TRUE, INFINITE);
                    for (int i = 0; i < udpThreadCount; i++) {
                        CloseHandle(udpHandles[i]);
                    }
                }
                free(udpHandles);
            }
            if (udpProgHandle) {
                udpCtx.stopFlag = 1;
                WaitForSingleObject(udpProgHandle, INFINITE);
                CloseHandle(udpProgHandle);
                printf("\n");
            }
        }

        WSACleanup();
        if (portList) free(portList);
    }

    append(output, "\n");
    for (int i = 0; i < g_ipCount; i++) {
        IPResult* ipRes = &g_ipResults[i];
        if (ipRes->detailCount > 0) {
            for (int j = 0; j < ipRes->detailCount; j++) {
                append(output, "%s\n", ipRes->details[j]);
            }
            if (isRangeScan && (i != g_ipCount - 1)) {
                append(output, "------------------\n");
            }
        }
    }

    if (g_supportsANSI)
        append(output, "\033[33m");

    append(output, "\nSummary:\n");
    if (g_supportsANSI)
        append(output, "\033[0m");

    for (int i = 0; i < g_ipCount; i++) {
        IPResult* ipRes = &g_ipResults[i];
        if (ipRes->openCount > 0 || ipRes->openUdpCount > 0) {
            if (g_isPingOnly) {
                if (ipRes->netbiosName[0] != '\0') {
                    append(output, "%s (%s) responded to ping\n", ipRes->ip, ipRes->netbiosName);
                }
                else
                {
                    append(output, "%s responded to ping\n", ipRes->ip);
                }
            }
            else {
                if (ipRes->netbiosName[0] != '\0') {
                    append(output, "%s (%s): ", ipRes->ip, ipRes->netbiosName);
                }
                else {
                    append(output, "%s: ", ipRes->ip);
                }

                if (ipRes->openCount > 0) {
                    qsort(ipRes->openPorts, ipRes->openCount, sizeof(int), cmp_int);
                    append(output, "TCP ");
                    for (int j = 0; j < ipRes->openCount; j++) {
                        append(output, "%d%s", ipRes->openPorts[j], (j < ipRes->openCount - 1 ? "," : ""));
                    }
                }

                if (ipRes->openUdpCount > 0) {
                    if (ipRes->openCount > 0) append(output, " | ");
                    qsort(ipRes->openUdpPorts, ipRes->openUdpCount, sizeof(int), cmp_int);
                    append(output, "UDP ");
                    for (int j = 0; j < ipRes->openUdpCount; j++) {
                        append(output, "%d%s", ipRes->openUdpPorts[j], (j < ipRes->openUdpCount - 1 ? "," : ""));
                    }
                }
                append(output, "\n");
            }
        }
    }

    DWORD endTime = GetTickCount();
    DWORD elapsedTime = endTime - startTime;
    double seconds = elapsedTime / 1000.0;
    append(output, "\nScan Duration: %.2f s\n", seconds);

    cleanup_ip_results();
    return 0;
}

int Execute(char* argsBuffer, uint32_t bufferSize, goCallback callback) {
    output = NewOutput(128, callback);
    if (!output) {
        static char allocFailMsg[] = "[!] Failed to allocate output buffer\n";
        if (callback) {
            callback(allocFailMsg, (int)strlen(allocFailMsg));
        }
        return 1;
    }

    g_threadLimit = G_THREAD_LIMIT;
    g_ctimeout = G_TIMEOUT_DEFAULT;
    g_rechecks = G_RECHECKS;
    g_pingEnabled = 1;
    g_isPingOnly = 0;
    g_netbiosEnabled = 0;
    g_udpEnabled = 0;
    g_udpDelay = 100;
    if (g_udpPorts) { free(g_udpPorts); g_udpPorts = NULL; }
    g_udpPortCount = 0;
    int isNoPorts = 0;

    if (bufferSize < 1) {
        append(output, "[!] Usage: <target> [portRange] [options]\n");
        return failure(output);
    }

    char* buf = (char*)malloc(bufferSize + 1);
    if (buf == NULL) {
        append(output, "[!] Memory allocation error.\n");
        return failure(output);
    }
    memcpy(buf, argsBuffer, bufferSize);
    buf[bufferSize] = '\0';
    buf[strcspn(buf, "\r\n")] = '\0';

    if (strstr(buf, "-h") != NULL) {
        append(output, "Usage: <target> [portRange] [options]\n");
        append(output, "  target:    Hostname (e.g., scanme.nmap.org), single IP, or range (192.168.1.1-100)\n");
        append(output, "  portRange: Single port, range (80-90), comma-separated list (22,80,443), or 'all'\n");
        append(output, "Options:\n");
        append(output, "  -T <num>:  Set thread limit (default: 20, max: 50)\n");
        append(output, "  -t <ms>:   Set port scan timeout in msec (default: 100)\n");
        append(output, "  -r <num>:  Set extra rechecks for unanswered ports (default: 0, max: 10)\n");
        append(output, "  -Pn:       Disable ping (skip host discovery)\n");
        append(output, "  -i:        Perform ping scan only (skip port scan)\n");
        append(output, "  -sU:       Enable UDP scan (uses TOP 16 UDP ports if no ports specified)\n");
        append(output, "  -d <ms>:   Set delay between UDP ports in msec (default: 100)\n");
        append(output, "  -Nb:       Enable hostname resolution via reverse DNS lookup\n");
        append(output, "  -h:        Display this help message\n");
        append(output, "\nUDP Scanning Notes:\n");
        append(output, "  Default UDP ports: 53,67,68,69,88,123,137,138,161,389,500,514,623,1194,1900,5353\n");
        append(output, "  Protocol-specific probes sent for 12 services (21 probes total)\n");
        append(output, "  UDP scanning is slower due to ICMP rate limiting on targets\n");
        free(buf);
        return success(output);
    }

    char* targetRange = NULL;
    char* portRange = NULL;
    bool pingOnlyFlag = false;

    char* token = strtok(buf, " ");
    while (token != NULL) {
        if (token[0] == '-') {
            if (strncmp(token, "-T", 2) == 0) {
                const char* valueStr = token + 2;
                if (*valueStr == '\0') { valueStr = strtok(NULL, " "); }
                if (valueStr) g_threadLimit = atoi(valueStr);
                if (g_threadLimit > 50 || g_threadLimit < 1) g_threadLimit = 50;
            }
            else if (strncmp(token, "-t", 2) == 0) {
                const char* valueStr = token + 2;
                if (*valueStr == '\0') { valueStr = strtok(NULL, " "); }
                if (valueStr) g_ctimeout = atoi(valueStr);
                if (g_ctimeout < 10) g_ctimeout = 10;
            }
            else if (strncmp(token, "-r", 2) == 0) {
                const char* valueStr = token + 2;
                if (*valueStr == '\0') { valueStr = strtok(NULL, " "); }
                if (valueStr) g_rechecks = atoi(valueStr);
                if (g_rechecks > 10 || g_rechecks < 0) g_rechecks = 10;
            }
            else if (strcmp(token, "-Pn") == 0) {
                g_pingEnabled = 0;
            }
            else if (strcmp(token, "-i") == 0) {
                pingOnlyFlag = true;
            }
            else if (strcmp(token, "-Nb") == 0) {
                g_netbiosEnabled = 1;
            }
            else if (strcmp(token, "-sU") == 0) {
                g_udpEnabled = 1;
            }
            else if (strncmp(token, "-d", 2) == 0) {
                const char* valueStr = token + 2;
                if (*valueStr == '\0') { valueStr = strtok(NULL, " "); }
                if (valueStr) g_udpDelay = atoi(valueStr);
                if (g_udpDelay < 0) g_udpDelay = 0;
            }
        }
        else {
            if (targetRange == NULL) {
                targetRange = _strdup(token);
            }
            else if (portRange == NULL) {
                portRange = _strdup(token);
            }
        }
        token = strtok(NULL, " ");
    }
    free(buf);

    if (targetRange == NULL) {
        append(output, "[!] No target specified. Use -h for help.\n");
        if (portRange) free(portRange);
        return failure(output);
    }

    if (pingOnlyFlag) {
        g_isPingOnly = 1;
        if (portRange) {
            free(portRange);
            portRange = NULL;
        }
    }
    else {
        if (portRange == NULL) {
            portRange = _strdup("20,21,22,23,25,53,65,66,69,80,88,110,111,135,139,143,194,389,443,445,464,465,587,593,636,873,993,995,1194,1433,1494,1521,1540,1666,1801,1812,1813,2049,2179,2222,2383,2598,3000,3128,3268,3269,3306,3333,3389,4444,4848,5000,5044,5060,5061,5432,5555,5601,5631,5666,5671,5672,5693,5900,5931,5938,5984,5985,5986,6160,6200,6379,6443,6600,6771,7001,7474,7687,7777,7990,8000,8006,8080,8081,8082,8086,8088,8090,8091,8200,8443,8444,8500,8529,8530,8531,8600,8888,8912,9000,9042,9080,9090,9092,9160,9200,9229,9300,9389,9443,9515,9999,10000,10001,10011,10050,10051,11211,15672,17990,27015,27017,30033,47001");
            isNoPorts = 1;
        }
        g_isPingOnly = 0;
    }

    int udpUsingDefault = 0;
    if (g_udpEnabled && !g_isPingOnly) {
        const char* udpPortSpec = portRange;
        if (isNoPorts) {
            udpPortSpec = DEFAULT_UDP_PORTS;
            udpUsingDefault = 1;
        }
        if (!parse_ports(udpPortSpec, &g_udpPorts, &g_udpPortCount)) {
            append(output, "[!] Invalid UDP port specification.\n");
            free(targetRange);
            if (portRange) free(portRange);
            return failure(output);
        }
    }

    if (!g_headerPrintedStdout) {
        print_header_stdout();
        g_headerPrintedStdout = true;
    }

    if (g_supportsANSI) printf("\033[97m");
    printf("[.] Scanning Target: %s\n", targetRange);
    if (!g_isPingOnly) {
        if (!isNoPorts) printf("[.] TCP ports: %s\n", portRange);
        else printf("[.] TCP ports: TOP 123\n");
        if (g_udpEnabled) {
            if (udpUsingDefault) printf("[.] UDP ports: TOP 16 (53,67,68,69,88,123,137,138,161,389,500,514,623,1194,1900,5353)\n");
            else printf("[.] UDP ports: %s\n", portRange);
        }
    } else {
        printf("[.] Ping-only scan mode\n");
    }
    printf("[.] Threads: %d   Rechecks: %d   Timeout: %d ms", g_threadLimit, g_rechecks, g_ctimeout);
    if (g_udpEnabled) printf("   UDP delay: %d ms", g_udpDelay);
    printf("\n");
    if (!g_pingEnabled) printf("[.] Ping disabled (-Pn flag used)\n");
    if (g_supportsANSI) printf("\033[0m");
    printf("\n");

    int scanResult = run_port_scan(targetRange, portRange);

    free(targetRange);
    if (portRange) {
        free(portRange);
    }

    int exitCode = (scanResult == 0) ? success(output) : failure(output);
    output = NULL;
    return exitCode;
}

int console_callback(char* text, int len) {
    printf("%s", text);
    return 0;
}

int main(int argc, char* argv[]) {
    initConsoleColorSupport();
    if (argc < 2) {
        print_header_stdout();
        g_headerPrintedStdout = true;
        printf("Usage: <target> [portRange] [options]\n");
        printf("Use -h for more details.\n");
        return 1;
    }

    char argsBuffer[1024] = { 0 };
    int pos = 0;
    for (int i = 1; i < argc; i++) {
        int n = snprintf(argsBuffer + pos, sizeof(argsBuffer) - pos, "%s ", argv[i]);
        if (n < 0 || n >= (int)(sizeof(argsBuffer) - pos))
            break;
        pos += n;
    }

    return Execute(argsBuffer, (uint32_t)strlen(argsBuffer), console_callback);
}
