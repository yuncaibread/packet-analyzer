"""Packet sniffer module for capturing network traffic.

This module provides the PacketSniffer class which handles capturing
network packets from specified network interfaces.
"""

import logging
from typing import Callable, Optional, List
from scapy.all import sniff, get_if_list

logger = logging.getLogger(__name__)


class PacketSniffer:
    """Captures network packets from network interfaces.

    This class provides functionality to sniff packets from a specified
    network interface with optional filtering and callback mechanisms.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        packet_count: int = 0,
        filter_expr: str = "",
        timeout: Optional[int] = None,
    ):
        """Initialize the packet sniffer.

        Args:
            interface: Network interface to sniff on (e.g., 'eth0').
                      If None, uses the default interface.
            packet_count: Maximum number of packets to capture (0 = infinite).
            filter_expr: BPF filter expression (e.g., 'tcp port 80').
            timeout: Timeout in seconds for sniffing (None = no timeout).
        """
        self.interface = interface
        self.packet_count = packet_count
        self.filter_expr = filter_expr
        self.timeout = timeout
        self.packets: List = []
        self._is_sniffing = False

    @staticmethod
    def get_available_interfaces() -> List[str]:
        """Get list of available network interfaces.

        Returns:
            List of interface names available on the system.
        """
        return get_if_list()

    def start_sniffing(
        self, packet_callback: Optional[Callable] = None
    ) -> List:
        """Start capturing packets.

        Args:
            packet_callback: Optional callback function to process each packet.

        Returns:
            List of captured packets.
        """
        self._is_sniffing = True
        logger.info(
            f"Starting packet capture on {self.interface or 'default interface'}"
        )

        try:
            packets = sniff(
                iface=self.interface,
                prn=packet_callback,
                filter=self.filter_expr,
                count=self.packet_count if self.packet_count > 0 else 0,
                timeout=self.timeout,
                store=True,
            )
            self.packets = list(packets)
            logger.info(f"Captured {len(self.packets)} packets")
            return self.packets
        except PermissionError:
            logger.error("Permission denied. Root privileges required to sniff packets.")
            raise
        except Exception as e:
            logger.error(f"Error during packet sniffing: {e}")
            raise
        finally:
            self._is_sniffing = False

    def stop_sniffing(self) -> None:
        """Stop packet sniffing."""
        self._is_sniffing = False
        logger.info("Stopped packet capture")

    def get_captured_packets(self) -> List:
        """Get list of captured packets.

        Returns:
            List of captured Scapy packet objects.
        """
        return self.packets

    def clear_packets(self) -> None:
        """Clear the captured packets list."""
        self.packets.clear()
        logger.debug("Cleared captured packets")
