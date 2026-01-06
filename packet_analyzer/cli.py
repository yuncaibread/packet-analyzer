"""Command-line interface for packet analyzer.

This module provides CLI commands for capturing and analyzing network packets.
"""

import logging
import sys
from typing import Optional
import click
from colorama import Fore, init as colorama_init

from packet_analyzer.sniffer import PacketSniffer
from packet_analyzer.analyzer import PacketAnalyzer
from packet_analyzer.parser import PacketParser

colorama_init(autoreset=True)
logger = logging.getLogger(__name__)


def setup_logging(verbose: bool) -> None:
    """Setup logging configuration.

    Args:
        verbose: Enable verbose logging if True.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


@click.group()
@click.option(
    "-v", "--verbose", is_flag=True, help="Enable verbose output"
)
def cli(verbose: bool) -> None:
    """Packet Analyzer - Network packet sniffer and analyzer.

    Capture, analyze, and inspect network traffic in real-time.
    """
    setup_logging(verbose)


@cli.command()
def interfaces() -> None:
    """List available network interfaces."""
    try:
        ifaces = PacketSniffer.get_available_interfaces()
        if not ifaces:
            click.echo(Fore.YELLOW + "No network interfaces found.")
            return

        click.echo(Fore.GREEN + "Available Network Interfaces:")
        for iface in ifaces:
            click.echo(f"  - {iface}")
    except Exception as e:
        click.echo(Fore.RED + f"Error listing interfaces: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "-i",
    "--interface",
    help="Network interface to sniff on (default: default interface)",
)
@click.option(
    "-c", "--count", type=int, default=10, help="Number of packets to capture (default: 10)"
)
@click.option(
    "-f",
    "--filter",
    default="",
    help="BPF filter expression (e.g., 'tcp port 80')",
)
@click.option(
    "-t", "--timeout", type=int, default=None, help="Timeout in seconds"
)
def sniff(
    interface: Optional[str],
    count: int,
    filter: str,
    timeout: Optional[int],
) -> None:
    """Capture network packets.

    Requires root/administrator privileges.
    """
    try:
        click.echo(Fore.CYAN + "Starting packet capture...")
        sniffer = PacketSniffer(
            interface=interface,
            packet_count=count,
            filter_expr=filter,
            timeout=timeout,
        )

        def packet_callback(packet):
            summary = PacketParser.format_packet_summary(packet)
            click.echo(f"{Fore.GREEN}[+]{Fore.RESET} {summary}")

        packets = sniffer.start_sniffing(packet_callback=packet_callback)
        click.echo(Fore.GREEN + f"\nCaptured {len(packets)} packets")

    except PermissionError:
        click.echo(
            Fore.RED + "Error: Root privileges required to sniff packets.",
            err=True,
        )
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo(Fore.YELLOW + "\nPacket capture interrupted by user.")
    except Exception as e:
        click.echo(Fore.RED + f"Error during packet capture: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "-i",
    "--interface",
    help="Network interface to sniff on",
)
@click.option(
    "-c", "--count", type=int, default=50, help="Number of packets to analyze (default: 50)"
)
@click.option(
    "-f",
    "--filter",
    default="",
    help="BPF filter expression",
)
def analyze(
    interface: Optional[str],
    count: int,
    filter: str,
) -> None:
    """Analyze captured network packets.

    Requires root/administrator privileges.
    """
    try:
        click.echo(Fore.CYAN + "Capturing packets for analysis...")
        sniffer = PacketSniffer(
            interface=interface,
            packet_count=count,
            filter_expr=filter,
        )

        packets = sniffer.start_sniffing()

        if not packets:
            click.echo(Fore.YELLOW + "No packets captured.")
            return

        click.echo(Fore.CYAN + "\nAnalyzing packets...")
        analyzer = PacketAnalyzer()
        stats = analyzer.analyze_packets(packets)

        # Display results
        click.echo(Fore.GREEN + "\n=== Analysis Results ===")
        click.echo(f"Total Packets: {stats['total_packets']}")

        click.echo(Fore.CYAN + "\nPacket Sizes:")
        sizes = stats["packet_sizes"]
        click.echo(f"  Min: {sizes['min']} bytes")
        click.echo(f"  Max: {sizes['max']} bytes")
        click.echo(f"  Average: {sizes['average']:.2f} bytes")
        click.echo(f"  Total: {sizes['total']} bytes")

        click.echo(Fore.CYAN + "\nProtocol Distribution:")
        for proto, count in stats["protocol_distribution"].items():
            click.echo(f"  {proto}: {count}")

        click.echo(Fore.CYAN + "\nTop Source IPs:")
        src_ips = stats["ip_statistics"]["source_ips"]
        for ip, count in sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            click.echo(f"  {ip}: {count}")

        click.echo(Fore.CYAN + "\nTop Destination IPs:")
        dst_ips = stats["ip_statistics"]["destination_ips"]
        for ip, count in sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            click.echo(f"  {ip}: {count}")

    except PermissionError:
        click.echo(
            Fore.RED + "Error: Root privileges required to sniff packets.",
            err=True,
        )
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo(Fore.YELLOW + "\nAnalysis interrupted by user.")
    except Exception as e:
        click.echo(Fore.RED + f"Error during analysis: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("packet_index", type=int, default=0)
@click.option(
    "-i",
    "--interface",
    help="Network interface to sniff on",
)
@click.option(
    "-c", "--count", type=int, default=1, help="Number of packets to capture"
)
def parse(
    packet_index: int,
    interface: Optional[str],
    count: int,
) -> None:
    """Parse and display detailed packet information.

    Requires root/administrator privileges.
    """
    try:
        click.echo(Fore.CYAN + "Capturing packet...")
        sniffer = PacketSniffer(
            interface=interface,
            packet_count=count,
        )

        packets = sniffer.start_sniffing()

        if not packets:
            click.echo(Fore.YELLOW + "No packets captured.")
            return

        if packet_index >= len(packets):
            click.echo(Fore.RED + f"Packet index {packet_index} out of range.")
            return

        click.echo(Fore.GREEN + f"\nParsing packet {packet_index}...\n")
        packet = packets[packet_index]
        parsed = PacketParser.parse_packet(packet)

        # Display parsed information
        _display_parsed_packet(parsed)

    except PermissionError:
        click.echo(
            Fore.RED + "Error: Root privileges required to sniff packets.",
            err=True,
        )
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo(Fore.YELLOW + "\nOperation interrupted by user.")
    except Exception as e:
        click.echo(Fore.RED + f"Error: {e}", err=True)
        sys.exit(1)


def _display_parsed_packet(parsed: dict) -> None:
    """Display parsed packet information in formatted output.

    Args:
        parsed: Parsed packet dictionary.
    """
    for layer_name, layer_data in parsed.items():
        if layer_data and isinstance(layer_data, dict):
            click.echo(Fore.CYAN + f"{layer_name.upper()}:")
            for key, value in layer_data.items():
                if isinstance(value, dict):
                    click.echo(f"  {key}:")
                    for k, v in value.items():
                        click.echo(f"    {k}: {v}")
                elif isinstance(value, list):
                    click.echo(f"  {key}: {value}")
                else:
                    click.echo(f"  {key}: {value}")
            click.echo()


def main() -> None:
    """Entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
