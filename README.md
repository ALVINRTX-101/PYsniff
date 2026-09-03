# PySniff — Python Packet Sniffer (Kali Linux)

A lightweight TCP/UDP/HTTP/HTTPS packet sniffer and analyzer built with
[Scapy](https://scapy.net/), designed to run on **Kali Linux**.

It captures live traffic, identifies TCP/UDP flows, parses plaintext
HTTP requests/responses, flags HTTPS (TLS-encrypted) sessions, and can
export results to `.pcap` and CSV for further analysis.

> ⚠️ **Authorized use only.** Only run this against networks, hosts,
> and interfaces you own or have explicit written permission to test.
> Unauthorized packet capture may violate the law in your
> jurisdiction (e.g. wiretapping / computer misuse statutes). This
> project is intended for education, CTF practice, and testing your
> own lab/home network.

## Features

- Live capture on any interface (`eth0`, `wlan0`, `lo`, etc.)
- Protocol breakdown: TCP, UDP, HTTP, HTTPS, DNS
- HTTP request/response parsing (method, path, Host, User-Agent, etc.)
- DNS query/response parsing (domain queried, resolved IPs)
- HTTPS traffic is identified by port/SNI metadata only — payload is
  never decrypted (this is not a MITM tool)
- Filter to a single host with `--target-ip` (source OR destination match)
- Live full-screen terminal dashboard (`--dashboard`) with running
  counters, top talkers, and a scrolling recent-packets view
- Custom BPF filters (`tcp port 80`, `host 10.0.0.5`, etc.)
- Save raw capture to `.pcap` (open in Wireshark)
- CSV analysis log for scripting/reporting
- Live packet counters and end-of-run summary (incl. top talkers)

## Requirements

- Kali Linux (tested on current Kali rolling release)
- Python 3.9+
- `scapy`
- Root privileges (raw sockets require it)

## Installation

```bash
git clone https://github.com/<your-username>/pysniff.git
cd pysniff
pip install -r requirements.txt --break-system-packages
```

Kali ships Python and libpcap already, but if `scapy` isn't installed
system-wide you can also grab it via apt:

```bash
sudo apt update && sudo apt install -y python3-scapy
```

## Usage

List available interfaces:

```bash
sudo python3 packet_sniffer.py --list-interfaces
```

Sniff all TCP/UDP traffic on `eth0`:

```bash
sudo python3 packet_sniffer.py -i eth0
```

Only show HTTP traffic:

```bash
sudo python3 packet_sniffer.py -i wlan0 --http-only
```

Capture 200 packets, save a pcap, and log analysis to CSV:

```bash
sudo python3 packet_sniffer.py -i eth0 -c 200 -o capture.pcap --log analysis.csv
```

Use a custom BPF filter:

```bash
sudo python3 packet_sniffer.py -i eth0 -f "tcp port 443"
```

Only show traffic to/from one host:

```bash
sudo python3 packet_sniffer.py -i eth0 --target-ip 192.168.1.20
```

Launch the live full-screen dashboard (counters, top talkers, recent
packets — press `q` to quit):

```bash
sudo python3 packet_sniffer.py -i eth0 --dashboard
```

Full options:

```
-i, --iface            Interface to sniff on
-f, --filter           BPF filter (default: "tcp or udp")
-c, --count            Number of packets to capture (0 = infinite)
--http-only            Only display HTTP traffic
--target-ip IP         Only show packets where IP is source or destination
--dashboard            Live full-screen terminal dashboard (press q to quit)
-o, --output           Save raw capture to a .pcap file
--log                  Write a CSV analysis log
--list-interfaces      List interfaces and exit
```

## Sample output

```
Sniffing on iface=eth0 filter='tcp or udp' count=infinite — Ctrl+C to stop

[2026-09-03 10:12:04.812] HTTP             192.168.1.20:52344 -> 93.184.216.34:80  len=412
    HTTP > GET /api/status HTTP/1.1 | Host: example.com | User-Agent: curl/8.4.0
[2026-09-03 10:12:05.001] HTTPS (encrypted) 192.168.1.20:52346 -> 142.250.premium:443  len=571
    HTTPS payload is TLS-encrypted; only metadata (IPs/ports/SNI) is visible without a MITM/keylog setup.
[2026-09-03 10:12:05.220] DNS              192.168.1.20:52130 -> 8.8.8.8:53  len=34
    DNS  > query example.com
```

## Why HTTPS shows no content

This tool does not perform TLS interception. HTTPS traffic is
identified and logged (source/destination, ports, packet size), but
the encrypted payload is not decoded. If you need to inspect your own
app's HTTPS traffic, look into tools that use `SSLKEYLOGFILE` with
Wireshark, or a consenting local proxy (e.g. mitmproxy) on traffic you
control.

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

This project is provided for educational and authorized
security-testing purposes only. The author(s) are not responsible for
misuse. By using this software you agree to comply with all applicable
laws.

## License

[MIT](LICENSE)
