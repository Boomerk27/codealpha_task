from scapy.all import *
import sys

def process_packet(packet):
    if packet.haslayer(IP):
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto = ip.proto
        proto_name = {6: 'TCP', 17: 'UDP'}.get(proto, f'Other ({proto})')
        length = len(packet)

        src_port, dst_port = "N/A", "N/A"
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        print("\n[+] Captured Packet:")
        print(f"    Source IP: {src_ip}")
        print(f"    Source Port: {src_port}")
        print(f"    Destination IP: {dst_ip}")
        print(f"    Destination Port: {dst_port}")
        print(f"    Protocol: {proto_name}")
        print(f"    Packet Length: {length}")

def main():
    iface = input(f"Enter interface (default: {conf.iface}): ") or conf.iface
    count = input("Enter number of packets to capture (0 for unlimited): ")
    count = int(count) if count.isdigit() else 0

    print("[*] Starting sniffer...")
    try:
        sniff(iface=iface, prn=process_packet, count=count, store=0)
    except PermissionError:
        print("Error: Permission denied. Run with sudo/Administrator.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")

if __name__ == "__main__":
    main()
