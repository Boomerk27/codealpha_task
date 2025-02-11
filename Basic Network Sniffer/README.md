**Network Sniffer in Python**
A lightweight network sniffer built with Python and Scapy to capture and analyze network traffic in real-time. This tool extracts key packet details, including source and destination IPs, ports, protocol types, and packet length.

🚀 Features

✔️ Captures TCP, UDP, and other network packets
✔️ Displays source IP, destination IP, ports, protocol, and packet length
✔️ Supports user-defined network interfaces
✔️ Allows custom packet count (capture limited or unlimited packets)
✔️ Lightweight and easy to use

🔧 Installation

Ensure you have Python installed, then install Scapy:
**pip install scapy**

💻 Usage

Run the script with admin/root privileges for full access:
**sudo python network_sniffer.py**

or on Windows (as Administrator):
**python network_sniffer.py**

⚙️ How It Works

Prompts for a network interface (default interface auto-selected).
Captures incoming/outgoing packets in real-time.
Extracts and prints relevant details of each packet.
Runs indefinitely or for a specified number of packets.

📜 Example Output

[+] Capturing Packets...
Source IP: 192.168.1.10 | Source Port: 443 | Destination IP: 192.168.1.5 | Destination Port: 52000 | Protocol: TCP | Packet Length: 1500
Source IP: 192.168.1.5 | Source Port: 52000 | Destination IP: 192.168.1.10 | Destination Port: 443 | Protocol: TCP | Packet Length: 60

⚠️ Notes

Requires root/admin privileges to access raw sockets.
Should be used only for legal and ethical purposes.
Works on Linux, macOS, and Windows (Windows users must install WinPcap or Npcap).

📜 License

This project is licensed under the MIT License – feel free to use and modify!
