#!/usr/bin/env python3
"""
sniffer.py
Basic Sniffer With Scapy:
- captures 15 packets
- displays: Source IP, Destination IP, protocol (name), and packet size
- output in a "pretty" multi-line format
"""

from scapy.all import sniff, IP, conf, get_if_list
import sys

# Number of packets to capture (defined MVP)
CAPTURE_COUNT = 15

# If you want to specify the interface, put it here as 'eth0', 'wlan0', 'Ethernet 2', etc.
# If None, Scapy uses the default interface (conf.iface)
INTERFACE = None  # Ex: 'eth0' or 'wlan0' or 'Ethernet'

# Simple mapping of IP protocol numbers to names
PROTO_MAP = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "ENCAP",
    89: "OSPF",
    # add more as needed, I will only use these
}

def protocolo_nome(proto_num):
    # Returns the protocol name based on the number, or UNKNOWN
    return PROTO_MAP.get(proto_num, f"UNKNOWN({proto_num})")

def packet_handler(packet):
    """Function called for each captured packet."""
    # Identifies if the packet has an IP l
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto_num = ip_layer.proto
        proto_name = protocolo_nome(proto_num)
        size = len(packet)  # packet size in bytes

        # "Pretty" multi-line printing
        print("=" * 40)
        print(f"Pacote capturado")
        print(f"Origem    : {src}")
        print(f"Destino   : {dst}")
        print(f"Protocolo : {proto_name}")
        print(f"Tamanho   : {size} bytes")
        print("=" * 40)
    else:
        # Packets without IP (e.g., ARP) — optional for visualization
        print("=" * 40)
        print("Pacote sem camada IP (ex: ARP/LLC)")
        print(f"Tamanho: {len(packet)} bytes")
        print("=" * 40)

def listar_interfaces():
    """Helper to list available interfaces (useful for choosing the INTERFACE)."""
    print("Interfaces de rede disponíveis:")
    for i, iface in enumerate(get_if_list(), 1):
        print(f"{i:02d}. {iface}")
    print(f"\nInterface padrão do Scapy: {conf.iface}")
    print("-" * 40)

def main():
    # Shows interfaces to help with selectionerfaces para ajudar a escolher
    listar_interfaces()

    # If INTERFACE was manually defined, pass it to sniff()
    sniff_args = {
        "count": CAPTURE_COUNT,
        "prn": packet_handler,
        # "store": False,  # optional to not store packets in memory
    }
    if INTERFACE:
        sniff_args["iface"] = INTERFACE

    print(f"Iniciando captura: {CAPTURE_COUNT} pacotes ...")
    print("Pressione Ctrl+C para interromper (se necessário).\n")
    try:
        sniff(**sniff_args)
    except PermissionError:
        print("Erro de permissão: execute o script com privilégios de administrador/root.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCaptura interrompida pelo usuário.")
    print("\nCaptura finalizada.")

if __name__ == "__main__":
    main()
