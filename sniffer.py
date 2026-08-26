#!/usr/bin/env python3
"""
===============================================================================
Network Packet Sniffer & Traffic Analyzer
===============================================================================
Author      : Aashu
Description : A raw-socket network packet sniffer built in Python for Linux.
              Captures live network traffic and parses Ethernet, IPv4,
              TCP, UDP, and ICMP headers without external libraries.
License     : MIT
===============================================================================
"""

import socket
import struct
import time
import sys


def get_mac_address(bytes_addr: bytes) -> str:
    """Format raw byte sequence into a human-readable MAC address (XX:XX:XX:XX:XX:XX)."""
    return ':'.join(f'{b:02x}' for b in bytes_addr)


def start_sniffer():
    """Main execution function to capture and parse network packets."""
    
    # Create raw socket (AF_PACKET for Linux link-layer capture)
    # ETH_P_ALL (3) captures all incoming/outgoing protocol frames
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("\n[!] Error: Root privileges required.")
        print("[!] Please run with 'sudo': sudo python3 sniffer.py\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Socket Creation Error: {e}\n")
        sys.exit(1)

    print("\n" + "=" * 65)
    print("  NETWORK PACKET SNIFFER & TRAFFIC ANALYZER")
    print("=" * 65)
    print("[+] Listening for live network packets...")
    print("[+] Saving captured data to 'capture_log.txt'")
    print("[+] Press Ctrl+C to stop.\n")
    print(f"{'#':<6} {'Protocol':<10} {'Source IP:Port':<22} {'Destination IP:Port':<22}")
    print("-" * 65)

    packet_count = 0

    try:
        with open("capture_log.txt", "a") as log_file:
            while True:
                # Receive raw frame (buffer size 65535 bytes)
                raw_data, _ = conn.recvfrom(65535)

                # -------------------------------------------------------------
                # 1. Parse Ethernet Header (First 14 bytes)
                # -------------------------------------------------------------
                eth_header = struct.unpack('!6s6sH', raw_data[:14])
                dest_mac = get_mac_address(eth_header[0])
                src_mac = get_mac_address(eth_header[1])
                eth_protocol = socket.htons(eth_header[2])

                # Process IPv4 packets only (EtherType 0x0800 -> 8)
                if eth_protocol == 8:
                    packet_count += 1
                    
                    # ---------------------------------------------------------
                    # 2. Parse IPv4 Header (Next 20 bytes: bytes 14 to 34)
                    # ---------------------------------------------------------
                    ip_header = struct.unpack('!BBHHHBBH4s4s', raw_data[14:34])
                    ip_proto_id = ip_header[6]
                    src_ip = socket.inet_ntoa(ip_header[8])
                    dest_ip = socket.inet_ntoa(ip_header[9])

                    # ---------------------------------------------------------
                    # 3. Parse Transport Layer (TCP / UDP / ICMP)
                    # ---------------------------------------------------------
                    if ip_proto_id == 6:
                        proto_name = "TCP"
                        tcp_header = struct.unpack('!HH', raw_data[34:38])
                        src_str = f"{src_ip}:{tcp_header[0]}"
                        dest_str = f"{dest_ip}:{tcp_header[1]}"

                    elif ip_proto_id == 17:
                        proto_name = "UDP"
                        udp_header = struct.unpack('!HH', raw_data[34:38])
                        src_str = f"{src_ip}:{udp_header[0]}"
                        dest_str = f"{dest_ip}:{udp_header[1]}"

                    elif ip_proto_id == 1:
                        proto_name = "ICMP"
                        src_str = src_ip
                        dest_str = dest_ip

                    else:
                        proto_name = f"IP({ip_proto_id})"
                        src_str = src_ip
                        dest_str = dest_ip

                    # Display formatted output in terminal
                    display_line = f"{packet_count:<6} {proto_name:<10} {src_str:<22} {dest_str:<22}"
                    print(display_line)

                    # Write structured data with timestamp to log file
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                    log_file.write(f"[{timestamp}] MAC: {src_mac} -> {dest_mac} | {display_line}\n")

    except KeyboardInterrupt:
        print("\n" + "-" * 65)
        print(f"[+] Sniffing stopped by user. Total packets captured: {packet_count}")
        print("[+] Log saved to 'capture_log.txt'.\n")
        conn.close()


if __name__ == "__main__":
    start_sniffer()
