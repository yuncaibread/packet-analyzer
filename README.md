# Packet Analyzer

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive network packet sniffer and analyzer written in Python. Capture, analyze, and inspect network traffic in real-time with support for multiple protocols and detailed traffic inspection.

## Features

- **Real-time Packet Capture**: Sniff packets from specified network interfaces
- **Protocol Support**: Analyze Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP, and DNS packets
- **Traffic Analysis**: Generate statistics on packet sizes, protocols, IP addresses, and ports
- **Detailed Parsing**: Extract complete information from each packet layer
- **Filtering**: Apply BPF (Berkeley Packet Filter) expressions for targeted capture
- **CLI Interface**: User-friendly command-line interface powered by Click
- **Colorized Output**: Enhanced readability with colored console output

## Requirements

- Python 3.7+
- Root/Administrator privileges (for packet capturing)
- Supported Operating Systems: Linux, macOS, Windows

## Installation

### From Source

1. Clone the repository:

```bash
git clone https://github.com/yuncaibread/packet-analyzer.git
cd packet-analyzer
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Install the package:

```bash
pip install -e .
```

### Using pip (after publishing to PyPI)

```bash
pip install packet-analyzer
```

## Quick Start

### List Available Network Interfaces

```bash
sudo packet-analyzer interfaces
```

### Capture Packets

Capture 10 packets from the default interface:

```bash
sudo packet-analyzer sniff -c 10
```

Capture packets from a specific interface:

```bash
sudo packet-analyzer sniff -i eth0 -c 20
```

Capture only TCP traffic on port 80:

```bash
sudo packet-analyzer sniff -f "tcp port 80" -c 50
```

### Analyze Packets

Capture and analyze 50 packets:

```bash
sudo packet-analyzer analyze -c 50
```

Analyze packets from a specific interface:

```bash
sudo packet-analyzer analyze -i eth0 -c 100
```

Analyze with filter:

```bash
sudo packet-analyzer analyze -f "tcp" -c 50
```

### Parse Packet Details

Capture and display detailed information for the first packet:

```bash
sudo packet-analyzer parse
```

Display detailed information for a specific packet:

```bash
sudo packet-analyzer parse 2
```

## Usage Examples

### Python API

```python
from packet_analyzer import PacketSniffer, PacketAnalyzer, PacketParser

# Capture packets
sniffer = PacketSniffer(interface='eth0', packet_count=20)
packets = sniffer.start_sniffing()

# Analyze packets
analyzer = PacketAnalyzer()
stats = analyzer.analyze_packets(packets)
print(f"Total packets: {stats['total_packets']}")
print(f"Protocol distribution: {stats['protocol_distribution']}")

# Parse individual packet
for packet in packets:
    parsed = PacketParser.parse_packet(packet)
    print(PacketParser.format_packet_summary(packet))
```

### With Filtering

```python
# Only capture HTTPS traffic
sniffer = PacketSniffer(
    interface='eth0',
    filter_expr='tcp port 443',
    packet_count=50
)
packets = sniffer.start_sniffing()

# Analyze
analyzer = PacketAnalyzer()
stats = analyzer.analyze_packets(packets)
```

## CLI Commands

### `interfaces`
List all available network interfaces.

```bash
sudo packet-analyzer interfaces
```

### `sniff`
Capture packets and display them in real-time.

**Options:**
- `-i, --interface`: Network interface to sniff on
- `-c, --count`: Number of packets to capture (default: 10)
- `-f, --filter`: BPF filter expression
- `-t, --timeout`: Timeout in seconds

```bash
sudo packet-analyzer sniff -c 20 -i eth0
```

### `analyze`
Capture and analyze packets with statistics.

**Options:**
- `-i, --interface`: Network interface to sniff on
- `-c, --count`: Number of packets to analyze (default: 50)
- `-f, --filter`: BPF filter expression

```bash
sudo packet-analyzer analyze -c 100
```

### `parse`
Capture and parse detailed packet information.

**Arguments:**
- `packet_index`: Index of packet to display (default: 0)

**Options:**
- `-i, --interface`: Network interface to sniff on
- `-c, --count`: Number of packets to capture (default: 1)

```bash
sudo packet-analyzer parse 0
```

## BPF Filter Examples

Capture TCP traffic:
```bash
sudo packet-analyzer sniff -f "tcp"
```

Capture HTTP traffic (port 80):
```bash
sudo packet-analyzer sniff -f "tcp port 80"
```

Capture DNS traffic (port 53):
```bash
sudo packet-analyzer sniff -f "udp port 53"
```

Capture traffic from specific IP:
```bash
sudo packet-analyzer sniff -f "src 192.168.1.100"
```

Capture traffic to specific IP:
```bash
sudo packet-analyzer sniff -f "dst 8.8.8.8"
```

Capture ICMP (ping):
```bash
sudo packet-analyzer sniff -f "icmp"
```

## Architecture

The project is organized into the following modules:

### `sniffer.py`
Handles packet capture from network interfaces using Scapy.

### `analyzer.py`
Provides statistical analysis of captured packets including protocol distribution, IP statistics, and port analysis.

### `parser.py`
Extracts detailed information from packets at all protocol layers.

### `cli.py`
Provides the command-line interface with Click for user interaction.

## Troubleshooting

### Permission Denied Error

Packet capturing requires root/administrator privileges:

```bash
sudo packet-analyzer sniff
```

On Linux, you can also grant capabilities to the Python binary:

```bash
sudo setcap cap_net_raw=ep /usr/bin/python3
```

### No Packets Captured

- Verify the interface name: `sudo packet-analyzer interfaces`
- Check if the interface is active and has network traffic
- Try a longer timeout: `sudo packet-analyzer sniff -t 30`

### Import Errors

Ensure all dependencies are installed:

```bash
pip install -r requirements.txt
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for educational and authorized security testing purposes only. Unauthorized access to network traffic is illegal. Always ensure you have proper authorization before capturing or analyzing network packets.

## Author

**yuncaibread** - [GitHub Profile](https://github.com/yuncaibread)

## See Also

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Click Documentation](https://click.palletsprojects.com/)
- [BPF Filter Syntax](https://www.tcpdump.org/papers/sniffing-faq.html)
