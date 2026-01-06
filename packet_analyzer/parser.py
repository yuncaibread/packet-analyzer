"""Packet parser module for extracting detailed packet information.

This module provides the PacketParser class which extracts and formats
detailed information from network packets.
"""

import logging
from typing import Dict, Any, Optional
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR

logger = logging.getLogger(__name__)


class PacketParser:
    """Parses network packets and extracts detailed information.

    This class provides methods to extract and format information from
    various layers of network packets.
    """

    @staticmethod
    def parse_packet(packet: Any) -> Dict[str, Any]:
        """Parse a complete packet and extract all available information.

        Args:
            packet: Scapy packet object to parse.

        Returns:
            Dictionary containing parsed packet information.
        """
        parsed = {
            "frame": PacketParser._parse_frame(packet),
            "layers": [],
        }

        if Ether in packet:
            parsed["ethernet"] = PacketParser._parse_ethernet(packet[Ether])

        if IP in packet:
            parsed["ipv4"] = PacketParser._parse_ipv4(packet[IP])
        elif IPv6 in packet:
            parsed["ipv6"] = PacketParser._parse_ipv6(packet[IPv6])

        if TCP in packet:
            parsed["tcp"] = PacketParser._parse_tcp(packet[TCP])
        elif UDP in packet:
            parsed["udp"] = PacketParser._parse_udp(packet[UDP])
        elif ICMP in packet:
            parsed["icmp"] = PacketParser._parse_icmp(packet[ICMP])

        if ARP in packet:
            parsed["arp"] = PacketParser._parse_arp(packet[ARP])

        if DNS in packet:
            parsed["dns"] = PacketParser._parse_dns(packet[DNS])

        return parsed

    @staticmethod
    def _parse_frame(packet: Any) -> Dict[str, Any]:
        """Parse frame-level information.

        Args:
            packet: Scapy packet object.

        Returns:
            Dictionary with frame information.
        """
        return {
            "length": len(packet),
            "time": packet.time if hasattr(packet, "time") else None,
        }

    @staticmethod
    def _parse_ethernet(eth_layer: Any) -> Dict[str, Any]:
        """Parse Ethernet layer information.

        Args:
            eth_layer: Scapy Ether layer object.

        Returns:
            Dictionary with Ethernet information.
        """
        return {
            "src_mac": eth_layer.src,
            "dst_mac": eth_layer.dst,
            "type": eth_layer.type,
        }

    @staticmethod
    def _parse_ipv4(ip_layer: Any) -> Dict[str, Any]:
        """Parse IPv4 layer information.

        Args:
            ip_layer: Scapy IP layer object.

        Returns:
            Dictionary with IPv4 information.
        """
        return {
            "version": ip_layer.version,
            "header_length": ip_layer.ihl,
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "ttl": ip_layer.ttl,
            "protocol": ip_layer.proto,
            "total_length": ip_layer.len,
            "identification": ip_layer.id,
            "flags": ip_layer.flags,
        }

    @staticmethod
    def _parse_ipv6(ipv6_layer: Any) -> Dict[str, Any]:
        """Parse IPv6 layer information.

        Args:
            ipv6_layer: Scapy IPv6 layer object.

        Returns:
            Dictionary with IPv6 information.
        """
        return {
            "version": ipv6_layer.version,
            "src_ip": ipv6_layer.src,
            "dst_ip": ipv6_layer.dst,
            "traffic_class": ipv6_layer.tc,
            "flow_label": ipv6_layer.fl,
            "payload_length": ipv6_layer.plen,
            "next_header": ipv6_layer.nh,
            "hop_limit": ipv6_layer.hlim,
        }

    @staticmethod
    def _parse_tcp(tcp_layer: Any) -> Dict[str, Any]:
        """Parse TCP layer information.

        Args:
            tcp_layer: Scapy TCP layer object.

        Returns:
            Dictionary with TCP information.
        """
        return {
            "src_port": tcp_layer.sport,
            "dst_port": tcp_layer.dport,
            "sequence_num": tcp_layer.seq,
            "acknowledgment_num": tcp_layer.ack,
            "flags": str(tcp_layer.flags),
            "window_size": tcp_layer.window,
        }

    @staticmethod
    def _parse_udp(udp_layer: Any) -> Dict[str, Any]:
        """Parse UDP layer information.

        Args:
            udp_layer: Scapy UDP layer object.

        Returns:
            Dictionary with UDP information.
        """
        return {
            "src_port": udp_layer.sport,
            "dst_port": udp_layer.dport,
            "length": udp_layer.len,
        }

    @staticmethod
    def _parse_icmp(icmp_layer: Any) -> Dict[str, Any]:
        """Parse ICMP layer information.

        Args:
            icmp_layer: Scapy ICMP layer object.

        Returns:
            Dictionary with ICMP information.
        """
        return {
            "type": icmp_layer.type,
            "code": icmp_layer.code,
            "checksum": icmp_layer.chksum,
        }

    @staticmethod
    def _parse_arp(arp_layer: Any) -> Dict[str, Any]:
        """Parse ARP layer information.

        Args:
            arp_layer: Scapy ARP layer object.

        Returns:
            Dictionary with ARP information.
        """
        return {
            "operation": arp_layer.op,
            "src_mac": arp_layer.hwsrc,
            "src_ip": arp_layer.psrc,
            "dst_mac": arp_layer.hwdst,
            "dst_ip": arp_layer.pdst,
        }

    @staticmethod
    def _parse_dns(dns_layer: Any) -> Dict[str, Any]:
        """Parse DNS layer information.

        Args:
            dns_layer: Scapy DNS layer object.

        Returns:
            Dictionary with DNS information.
        """
        dns_info = {
            "transaction_id": dns_layer.id,
            "is_response": bool(dns_layer.qr),
            "opcode": dns_layer.opcode,
            "response_code": dns_layer.rcode,
        }

        if dns_layer.qd:
            dns_info["queries"] = [
                {"name": q.qname.decode() if isinstance(q.qname, bytes) else q.qname}
                for q in dns_layer.qd
            ]

        if dns_layer.an:
            dns_info["answers"] = [
                {"name": rr.rrname.decode() if isinstance(rr.rrname, bytes) else rr.rrname}
                for rr in dns_layer.an
            ]

        return dns_info

    @staticmethod
    def format_packet_summary(packet: Any) -> str:
        """Create a human-readable summary of a packet.

        Args:
            packet: Scapy packet object.

        Returns:
            Formatted string summary of the packet.
        """
        summary_parts = []

        if Ether in packet:
            eth = packet[Ether]
            summary_parts.append(f"Ether: {eth.src} -> {eth.dst}")

        if IP in packet:
            ip = packet[IP]
            summary_parts.append(f"IP: {ip.src} -> {ip.dst}")

        if TCP in packet:
            tcp = packet[TCP]
            summary_parts.append(f"TCP: {tcp.sport} -> {tcp.dport}")
        elif UDP in packet:
            udp = packet[UDP]
            summary_parts.append(f"UDP: {udp.sport} -> {udp.dport}")

        return " | ".join(summary_parts) if summary_parts else "Unknown packet"
