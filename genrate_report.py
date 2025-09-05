import pyshark
from collections import Counter
import argparse

def generate_report(pcap_file):
    cap = pyshark.FileCapture(pcap_file)

    protocol_count = Counter()
    ip_addresses = set()
    port_count = Counter()

    for packet in cap:
        if 'ip' in packet:
            ip_addresses.add(packet.ip.src)
            ip_addresses.add(packet.ip.dst)
            protocol_count[packet.transport_layer] += 1
            if hasattr(packet, 'tcp'):
                port_count[packet.tcp.srcport] += 1
                port_count[packet.tcp.dstport] += 1

    report = f"Report for {pcap_file}\n"
    report += "Total Packets: {}\n".format(len(cap))
    report += "Unique IP Addresses: {}\n".format(len(ip_addresses))
    report += "Protocols:\n"
    
    for protocol, count in protocol_count.items():
        report += f"  {protocol}: {count}\n"

    report += "Ports:\n"
    
    for port, count in port_count.items():
        report += f"  Port {port}: {count}\n"

    return report

report = generate_report(".pcap")

with open("report.txt", "w") as f:
    f.write(report)

print("Report saved to report.txt")
