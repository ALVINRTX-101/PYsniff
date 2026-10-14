#!/usr/bin/env python3
"""
PySniff — Packet Sniffer Tool (Python + Scapy) for Kali Linux
================================================================
Captures live traffic and analyzes TCP / UDP / HTTP / HTTPS / DNS
packets, with optional live terminal dashboard and target-IP filtering.

IMPORTANT / LEGAL NOTICE
-------------------------
Only run this on networks and devices you own or have explicit
authorization to monitor. Capturing traffic on networks you don't
control (or don't have permission for) may be illegal in your
jurisdiction. This tool is intended for learning, debugging your own
apps, and monitoring your own home/lab network.

Requirements
------------
    sudo apt update && sudo apt install -y python3-scapy   # Kali (recommended)
    # or: pip install scapy --break-system-packages

Must be run with root privileges (sudo), since raw packet capture
requires it.

Usage examples
--------------
    sudo python3 packet_sniffer.py                          # sniff all TCP/UDP on default iface
    sudo python3 packet_sniffer.py -i eth0                   # choose interface
    sudo python3 packet_sniffer.py -f "tcp port 80"           # custom BPF filter
    sudo python3 packet_sniffer.py --http-only                # only show HTTP traffic
    sudo python3 packet_sniffer.py --target-ip 192.168.1.20   # only packets to/from this IP
    sudo python3 packet_sniffer.py --dashboard                # live terminal dashboard
    sudo python3 packet_sniffer.py -c 200                      # stop after 200 packets
    sudo python3 packet_sniffer.py -o capture.pcap             # also save raw capture to pcap
    sudo python3 packet_sniffer.py --log analysis.csv          # write a CSV analysis log

List interfaces:
    sudo python3 packet_sniffer.py --list-interfaces
"""

import argparse
import csv
import curses
import datetime
import os
import sys
import threading
import time
from collections import Counter, deque

try:
    from scapy.all import (
        sniff, wrpcap, get_if_list, conf,
        IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR
    )
except ImportError:
    sys.exit(
        "scapy is not installed.\n"
        "Install it with:  sudo apt install python3-scapy\n"
        "or:                pip install scapy --break-system-packages"
    )

# ----------------------------------------------------------------------
# Well-known ports we treat specially
HTTP_PORTS = {80, 8080, 8000}
HTTPS_PORTS = {443, 8443}
DNS_PORT = 53

# Keep some running stats
stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "http": 0,
    "https": 0,
    "dns": 0,
    "other": 0,
}
talkers = Counter()          # ip -> packet count, for dashboard "top talkers"
recent_lines = deque(maxlen=12)  # last N lines, for dashboard

csv_writer = None
csv_file = None
pcap_packets = []
args = None  # populated in main()
stop_event = threading.Event()


def human_time(ts=None):
    return datetime.datetime.fromtimestamp(ts or datetime.datetime.now().timestamp()).strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )[:-3]


def classify_app_protocol(sport, dport, payload_bytes):
    """Best-effort guess of application protocol from ports/payload."""
    ports = {sport, dport}
    if DNS_PORT in ports:
        return "DNS"
    if ports & HTTPS_PORTS:
        return "HTTPS (encrypted)"
    if ports & HTTP_PORTS:
        return "HTTP"
    if payload_bytes:
        # Sometimes HTTP runs on non-standard ports; sniff the payload itself
        head = payload_bytes[:4]
        if head in (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"HTTP"):
            return "HTTP"
    return None


def try_decode_http(payload_bytes):
    """Return a short printable snippet of an HTTP request/response, or None."""
    try:
        text = payload_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None
    lines = text.split("\r\n")
    if not lines:
        return None
    first_line = lines[0]
    if not (
        first_line.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS "))
        or first_line.startswith("HTTP/")
    ):
        return None
    interesting = [first_line]
    for line in lines[1:15]:
        if line.lower().startswith(("host:", "user-agent:", "content-type:", "server:", "location:")):
            interesting.append(line)
        if line == "":
            break
    return " | ".join(interesting)[:300]


def try_decode_dns(pkt):
    """Return a short printable snippet of a DNS query/response, or None."""
    if not pkt.haslayer(DNS):
        return None
    dns = pkt[DNS]
    try:
        if dns.qr == 0 and dns.qdcount > 0 and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            return f"query {qname}"
        if dns.qr == 1:
            qname = ""
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            answers = []
            for i in range(dns.ancount):
                try:
                    rr = dns.an[i]
                    rdata = rr.rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode(errors="replace")
                    answers.append(str(rdata))
                except Exception:
                    continue
            ans_str = ", ".join(answers[:5]) if answers else "no answers"
            return f"response {qname} -> {ans_str}"
    except Exception:
        return None
    return None


def matches_target_filter(src_ip, dst_ip):
    if not args.target_ip:
        return True
    return args.target_ip in (src_ip, dst_ip)


def handle_packet(pkt):
    if not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    src_ip, dst_ip = ip_layer.src, ip_layer.dst

    if not matches_target_filter(src_ip, dst_ip):
        return

    proto = None
    sport = dport = None
    payload = b""

    if pkt.haslayer(TCP):
        proto = "TCP"
        tcp_layer = pkt[TCP]
        sport, dport = tcp_layer.sport, tcp_layer.dport
        stats["tcp"] += 1
    elif pkt.haslayer(UDP):
        proto = "UDP"
        udp_layer = pkt[UDP]
        sport, dport = udp_layer.sport, udp_layer.dport
        stats["udp"] += 1
    else:
        stats["other"] += 1
        return  # scope is TCP/UDP only

    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)

    app_proto = classify_app_protocol(sport, dport, payload)
    extra_snippet = None

    if app_proto == "DNS":
        stats["dns"] += 1
        extra_snippet = try_decode_dns(pkt)
    elif app_proto == "HTTP":
        stats["http"] += 1
        extra_snippet = try_decode_http(payload)
    elif app_proto == "HTTPS (encrypted)":
        stats["https"] += 1

    stats["total"] += 1
    talkers[src_ip] += 1
    talkers[dst_ip] += 1

    label = app_proto or proto
    line = f"[{human_time()}] {label:16s} {src_ip}:{sport} -> {dst_ip}:{dport}  len={len(payload)}"

    detail = None
    if extra_snippet and app_proto == "DNS":
        detail = f"    DNS  > {extra_snippet}"
    elif extra_snippet and app_proto == "HTTP":
        detail = f"    HTTP > {extra_snippet}"
    elif app_proto == "HTTPS (encrypted)":
        detail = "    HTTPS payload is TLS-encrypted; only metadata (IPs/ports/SNI) is visible without a MITM/keylog setup."
    elif payload and not args.http_only:
        preview = payload[:48]
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in preview)
        detail = f"    payload preview: {printable}"

    if args.dashboard:
        recent_lines.append(line)
        if detail:
            recent_lines.append(detail)
    else:
        print(line)
        if detail:
            print(detail)

    if csv_writer:
        csv_writer.writerow([
            human_time(), proto, label, src_ip, sport, dst_ip, dport,
            len(payload), extra_snippet or ""
        ])
        csv_file.flush()

    if args.output:
        pcap_packets.append(pkt)


def print_summary():
    print("\n" + "=" * 60)
    print("Capture summary")
    print("=" * 60)
    print(f"Total TCP/UDP packets : {stats['total']}")
    print(f"  TCP                : {stats['tcp']}")
    print(f"  UDP                : {stats['udp']}")
    print(f"  HTTP (parsed)      : {stats['http']}")
    print(f"  HTTPS (encrypted)  : {stats['https']}")
    print(f"  DNS (parsed)       : {stats['dns']}")
    if talkers:
        print("\nTop talkers:")
        for ip, count in talkers.most_common(5):
            print(f"  {ip:<18} {count} packets")
    if args.output and pcap_packets:
        wrpcap(args.output, pcap_packets)
        print(f"\nSaved {len(pcap_packets)} packets to {args.output}")
    if csv_file:
        csv_file.close()
        print(f"Analysis log written to {args.log}")


# ----------------------------------------------------------------------
# Live terminal dashboard (curses)

def run_dashboard(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)

    sniff_thread = threading.Thread(target=run_sniff, daemon=True)
    sniff_thread.start()

    while not stop_event.is_set():
        try:
            key = stdscr.getch()
            if key in (ord("q"), ord("Q")):
                stop_event.set()
                break
        except Exception:
            pass

        stdscr.erase()
        h, w = stdscr.getmaxyx()

        header = f" PySniff dashboard | iface={args.iface or 'default'} | target={args.target_ip or 'any'} | q=quit "
        stdscr.addnstr(0, 0, header.ljust(w), w, curses.A_REVERSE)

        stdscr.addnstr(2, 0, f"Total: {stats['total']}   TCP: {stats['tcp']}   UDP: {stats['udp']}   "
                              f"HTTP: {stats['http']}   HTTPS: {stats['https']}   DNS: {stats['dns']}", w)

        stdscr.addnstr(4, 0, "Top talkers:", w, curses.A_BOLD)
        row = 5
        for ip, count in talkers.most_common(5):
            if row >= h - 2:
                break
            stdscr.addnstr(row, 2, f"{ip:<18} {count} packets", w)
            row += 1

        divider_row = row + 1
        if divider_row < h - 1:
            stdscr.addnstr(divider_row, 0, "-" * (w - 1), w)
        log_start = divider_row + 1
        stdscr.addnstr(log_start, 0, "Recent packets:", w, curses.A_BOLD)

        visible_rows = max(0, h - log_start - 2)
        lines_to_show = list(recent_lines)[-visible_rows:] if visible_rows else []
        for i, text_line in enumerate(lines_to_show):
            r = log_start + 1 + i
            if r >= h - 1:
                break
            stdscr.addnstr(r, 2, text_line, max(0, w - 2))

        stdscr.refresh()
        time.sleep(0.2)


def run_sniff():
    try:
        sniff(
            iface=args.iface,
            filter=resolve_bpf_filter(),
            prn=handle_packet,
            count=args.count if args.count > 0 else 0,
            store=False,
            stop_filter=lambda p: stop_event.is_set(),
        )
    except Exception:
        pass
    finally:
        stop_event.set()


def resolve_bpf_filter():
    bpf_filter = args.filter
    if args.http_only:
        bpf_filter = "tcp port 80 or tcp port 8080 or tcp port 8000"
    return bpf_filter


def main():
    global args, csv_writer, csv_file

    parser = argparse.ArgumentParser(description="Educational packet sniffer (TCP/UDP/HTTP/HTTPS/DNS)")
    parser.add_argument("-i", "--iface", help="Network interface to sniff on (default: scapy's default)")
    parser.add_argument("-f", "--filter", default="tcp or udp", help="BPF filter (default: 'tcp or udp')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("--http-only", action="store_true", help="Only display HTTP traffic")
    parser.add_argument("--target-ip", help="Only show packets where this IP is source or destination")
    parser.add_argument("--dashboard", action="store_true", help="Show a live terminal dashboard instead of a scrolling log")
    parser.add_argument("-o", "--output", help="Save raw capture to this .pcap file")
    parser.add_argument("--log", help="Write a CSV analysis log to this file")
    parser.add_argument("--list-interfaces", action="store_true", help="List available interfaces and exit")
    args = parser.parse_args()

    if args.list_interfaces:
        for name in get_if_list():
            print(name)
        return

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("Warning: not running as root — capture will likely fail. Run with sudo.")

    if args.log:
        csv_file = open(args.log, "w", newline="")
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["time", "l4_proto", "app_proto", "src_ip", "src_port", "dst_ip", "dst_port", "payload_len", "detail"])

    if args.dashboard:
        try:
            curses.wrapper(run_dashboard)
        except KeyboardInterrupt:
            stop_event.set()
        finally:
            print_summary()
        return

    bpf_filter = resolve_bpf_filter()
    print(f"Sniffing on iface={args.iface or 'default'} filter='{bpf_filter}' "
          f"target={args.target_ip or 'any'} count={'infinite' if args.count == 0 else args.count} — Ctrl+C to stop\n")

    try:
        sniff(
            iface=args.iface,
            filter=bpf_filter,
            prn=handle_packet,
            count=args.count if args.count > 0 else 0,
            store=False,
        )
    except PermissionError:
        sys.exit("Permission denied — run this script with sudo/root privileges.")
    except KeyboardInterrupt:
        pass
    finally:
        print_summary()


if __name__ == "__main__":
    main()
