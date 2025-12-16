# 📡 Network Packet Sniffer (Python + Scapy)

This project implements a basic network packet sniffer using the **Scapy** library.
The goal is to capture packets from the network interface, analyze their main information, and practically observe how data flows in a TCP/IP network.

---

##  Project Goals

- Build a Python program capable of capturing network packets in real-time.
- Understand the structure of captured packets (IP layer, protocol, size, etc.).
- Analyze how data travels through the network: broadcast, multicast, UDP, ARP, and others.
- Utilize appropriate libraries for packet capture (Scapy).
- Display important packet information:
  - Source IP
  - Destination IP
  - Protocol
  - Packet size
- Differentiate between packets with and without an IP layer (e.g., ARP).

---

## 🛠️ Technologies Used

- **Python 3.x**
- **Scapy**
- Development environment: PyCharm (optional)
- Windows + Npcap OR Linux/macOS

---

##  Prerequisites

### 🔹 Install Dependencies

```bash
pip install scapy

### 🔹 Windows (Required!)
Install Npcap with WinPcap API support: https://nmap.org/npcap/

Run PyCharm or the terminal as Administrator.

### 🔹 Linux/macOS
Run the script as root:

sudo python3 sniffer.py

```

---

##  How to Run the Script

- Clone this repository or download the files.
- Install the dependencies.
- Execute the script:
```
python sniffer.py

Or (Linux/macOS):

sudo python3 sniffer.py
```

### The program will:

• List available interfaces
• Start the capture
• Display 15 packets in a readable, formatted way

### Example Output

========================================
Packet Captured
Source    : 192.168.0.100
Destination : 224.0.0.7
Protocol  : UDP
Size      : 242 bytes
========================================

And for packets without an IP layer (like ARP):

========================================
Packet without IP layer (e.g., ARP/LLC)
Size: 42 bytes
========================================

---

## What I Learned from This Project

• How network sniffing works.
• Difference between broadcast, multicast, and unicast.
• Basic structure of an IP packet.
• Protocol identification (TCP, UDP, ICMP, etc.).
• How security tools analyze network traffic.
• How to use Scapy in practice.

## Possible Future Improvements

• Show TCP/UDP ports when present.
• Create filters (e.g., capture only TCP).
• Export to a .pcap file and open in Wireshark.
• Create a graphical interface.
• Create a continuous mode.

⚠️ Legal Disclaimer
This project was only for education purpose and should only be used on networks where you have authorization. Capturing traffic from third-party networks is illegal.
