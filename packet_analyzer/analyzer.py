"""Packet analysis module for extracting and analyzing packet information.

This module provides the PacketAnalyzer class which performs detailed
analysis on captured network packets.
"""

import logging
from typing import Dict, List, Any, Optional
from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

logger = logging.getLogger(__name__)


class PacketAnalyzer:
    """Analyzes captured network packets for various metrics and statistics.

    This class provides methods to extract information from packets and
    generate statistics about network traffic.
    """

    def __init__(self):
        """Initialize the packet analyzer."""
        self.packets = []
        self.statistics = {}

    def analyze_packets(self, packets: List) -> Dict[str, Any]:
        """Analyze a list of packets and generate statistics.

        Args:
            packets: List of Scapy packet objects to analyze.

        Returns:
            Dictionary containing analysis results and statistics.
        """
        self.packets = packets
        self.statistics = {
            "total_packets": len(packets),
            "packet_sizes": self._analyze_packet_sizes(packets),
            "protocol_distribution": self._analyze_protocols(packets),
            "ip_statistics": self._analyze_ip_addresses(packets),
            "port_statistics": self._analyze_ports(packets),
        }
        return self.statistics

    def _analyze_packet_sizes(self, packets: List) -> Dict[str, Any]:
        """Analyze packet size statistics.

        Args:
            packets: List of packets to analyze.

        Returns:
            Dictionary with packet size statistics.
        """
        if not packets:
            return {"min": 0, "max": 0, "average": 0, "total": 0}

        sizes = [len(p) for p in packets]
        return {
            "min": min(sizes),
            "max": max(sizes),
            "average": sum(sizes) / len(sizes),
            "total": sum(sizes),
        }

    def _analyze_protocols(self, packets: List) -> Dict[str, int]:
        """Analyze protocol distribution in packets.

        Args:
            packets: List of packets to analyze.

        Returns:
            Dictionary with protocol counts.
        """
        protocol_count = defaultdict(int)

        for packet in packets:
            if IP in packet:
                proto = packet[IP].proto
                if proto == 6:
                    protocol_count["TCP"] += 1
                elif proto == 17:
                    protocol_count["UDP"] += 1
                elif proto == 1:
                    protocol_count["ICMP"] += 1
                else:
                    protocol_count[f"IP_{proto}"] += 1
            elif IPv6 in packet:
                protocol_count["IPv6"] += 1
            else:
                protocol_count["Other"] += 1

        return dict(protocol_count)

    def _analyze_ip_addresses(self, packets: List) -> Dict[str, Any]:
        """Analyze source and destination IP addresses.

        Args:
            packets: List of packets to analyze.

        Returns:
            Dictionary with IP address statistics.
        """
        src_ips = defaultdict(int)
        dst_ips = defaultdict(int)

        for packet in packets:
            if IP in packet:
                src_ips[packet[IP].src] += 1
                dst_ips[packet[IP].dst] += 1

        return {
            "source_ips": dict(src_ips),
            "destination_ips": dict(dst_ips),
        }

    def _analyze_ports(self, packets: List) -> Dict[str, Any]:
        """Analyze source and destination ports.

        Args:
            packets: List of packets to analyze.

        Returns:
            Dictionary with port statistics.
        """
        src_ports = defaultdict(int)
        dst_ports = defaultdict(int)

        for packet in packets:
            if TCP in packet:
                src_ports[f"TCP_{packet[TCP].sport}"] += 1
                dst_ports[f"TCP_{packet[TCP].dport}"] += 1
            elif UDP in packet:
                src_ports[f"UDP_{packet[UDP].sport}"] += 1
                dst_ports[f"UDP_{packet[UDP].dport}"] += 1

        return {
            "source_ports": dict(src_ports),
            "destination_ports": dict(dst_ports),
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get the current analysis statistics.

        Returns:
            Dictionary containing analysis statistics.
        """
        return self.statistics

    def print_summary(self) -> None:
        """Print a summary of the analysis results."""
        if not self.statistics:
            print("No statistics available. Run analyze_packets() first.")
            return

        print("\n=== Packet Analysis Summary ===")
        print(f"Total Packets: {self.statistics['total_packets']}")
        print(f"\nPacket Sizes:")
        for key, value in self.statistics['packet_sizes'].items():
            print(f"  {key}: {value}")
        print(f"\nProtocol Distribution:")
        for proto, count in self.statistics['protocol_distribution'].items():
            print(f"  {proto}: {count}")
