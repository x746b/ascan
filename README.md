# ArtScan

ArtScan is a multiplatform, tiny, smart, and very fast port scanner written in C. It is perfect for pentesting and red team engagements.

---

> This fork adds UDP scanning to both Linux and Windows versions, plus unprivileged ICMP on Linux (no sudo required).

---

## Platforms

| Platform | Features | Directory |
|----------|----------|-----------|
| Linux | UDP scanning, unprivileged ICMP (no sudo) | [linux/](linux/) |
| Windows | UDP scanning | [windows/](windows/) |

## Features

* IP ranges and port ranges scan with threads and timeout adjustments
* Super fast smart scan of TOP 123 most common TCP ports by default
* UDP scanning with TOP 16 common UDP ports and protocol-specific probes
* No sudo required on Linux - uses unprivileged ICMP sockets (Linux 3.0+)
* Scan progress indicator
* Perform ping scan only (skip port scan)
* Capture banners and HTTP responses on open ports
* Scan by IP and FQDN
* Brief, sorted scan summary

## Quick Start

### Linux
```bash
cd linux
gcc -O2 -std=gnu11 -pthread -o ascan ascan.c
./ascan 192.168.1.1 -sU
```

### Windows
Open `windows/ascan.sln` in Visual Studio and build, or use pre-built binaries.
```
ascan.exe 192.168.1.1 -sU
```

## Usage

```
Usage: <target> [ports] [options]
  target:    Hostname (e.g., scanme.nmap.org), single IP, or range (192.168.1.1-100)
  ports:     Single port, range (80-90), comma-separated list (22,80,443), or 'all'
Options:
  -T <num>:  Set thread limit (default: 100 Linux, 20 Windows)
  -t <ms>:   Set port scan timeout in msec (default: 300)
  -r <num>:  Set extra rechecks for unanswered ports (default: 0)
  -Pn:       Disable ping (skip host discovery)
  -i:        Perform ping scan only (skip port scan)
  -sU:       Enable UDP scan (uses TOP 16 UDP ports if no ports specified)
  -d <ms>:   Set delay between UDP ports in msec (default: 100)
  -Nb:       Enable hostname resolution via reverse DNS lookup
  -h:        Display this help message
```

## Examples

```bash
# Basic TCP scan (TOP 123 ports)
./ascan 192.168.1.1

# TCP + UDP scan (TOP 123 TCP + TOP 16 UDP)
./ascan 192.168.1.1 -sU

# Scan specific ports (TCP + UDP)
./ascan 192.168.1.1 22,53,80,161,443 -sU

# Scan IP range
./ascan 192.168.1.1-254

# Skip ping, scan directly
./ascan 10.10.10.10 -Pn

# Ping sweep only
./ascan 192.168.1.1-254 -i
```

## UDP Scanning

Default UDP ports scanned with `-sU`: 53, 67, 68, 69, 88, 123, 137, 138, 161, 389, 500, 514, 623, 1194, 1900, 5353

Protocol-specific probes (sourced from [udpx](https://github.com/nullt3r/udpx)) are sent to known services. A response confirms the port as definitively **open** (green). Ports without probes fall back to a null byte and show `open|filtered` (cyan).

| Port | Service | Probes |
|------|---------|--------|
| 53 | DNS | 3 (NS, A, version.bind) |
| 67/68 | DHCP | null byte fallback |
| 69 | TFTP | 1 (RRQ) |
| 88 | Kerberos | 1 (AS-REQ) |
| 123 | NTP | 2 (NTPv4, NTPv2) |
| 137/138 | NetBIOS | 1 (NBSTAT) / fallback |
| 161 | SNMP | 3 (v1, v2c, v3) |
| 389 | CLDAP | 1 (root DSE) |
| 500 | IKE/IPsec | 2 (SA_INIT, malformed) |
| 514 | Syslog | null byte fallback |
| 623 | IPMI | 1 (RMCP) |
| 1194 | OpenVPN | 1 (HARD_RESET) |
| 1900 | SSDP/UPnP | 1 (M-SEARCH) |
| 5353 | mDNS | 1 (PTR reverse) |

The inter-port delay (`-d`, default 100ms) controls ICMP rate limiting avoidance. Lower values speed up scans on local networks; higher values are safer for remote targets.

## Fork Changes

- UDP scanning: Added `-sU` flag with smart default port list for common UDP services (both platforms)
- Protocol-specific UDP probes: 21 probes across 12 services for definitive open-port confirmation (Linux)
- Configurable UDP delay: `-d <ms>` flag to tune inter-port delay (default 100ms)
- Unprivileged ICMP (Linux): Uses `SOCK_DGRAM` ICMP sockets instead of raw sockets - no root/sudo required on modern Linux (3.0+)
- Separate port lists: TCP and UDP can use different port lists (UDP defaults to TOP 16 when not specified)
- Portable compilation: Fixed `linux/errqueue.h` include for musl-gcc static builds

## Credits

Original ArtScan by [@art3x](https://github.com/art3x)
