#!/usr/bin/env python3
import argparse
from colorama import init, Fore, Style
from .core.iotnet_core import IoTNetTool
from .core.interfaces import ConfigBuilder, OutputFormatter


class IoTNetOutputFormatter(OutputFormatter):
    """Custom output formatter for IoT network analysis results."""

    def _format_text(self, result: 'ToolResult') -> str:
        """Format IoT network analysis results as human-readable text."""
        if not result.success:
            return "\n".join(result.errors)

        if not result.data:
            return "No analysis data available."

        lines = []

        # Handle both single capture results and multiple file results
        if isinstance(result.data, dict) and 'total_packets' in result.data:
            # Single capture result (live capture)
            self._format_single_analysis(result.data, lines)
        else:
            # Multiple file results
            for file_path, file_data in result.data.items():
                lines.append(Fore.BLUE + f"Analysis for: {file_path}" + Style.RESET_ALL)
                lines.append("=" * 50)
                self._format_single_analysis(file_data, lines)
                lines.append("")

        return "\n".join(lines)

    def _format_single_analysis(self, data: dict, lines: list) -> None:
        """Format a single analysis result."""
        # Summary
        total_packets = data.get('total_packets', 0)
        lines.append(Fore.GREEN + f"Total packets analyzed: {total_packets}" + Style.RESET_ALL)

        # Capture info for live captures
        if 'capture_duration' in data:
            lines.append(Fore.CYAN + f"Live capture duration: {data['capture_duration']}s on interface {data['interface']}" + Style.RESET_ALL)

        # Protocol summary
        protocols = data.get('protocols', {})
        if protocols:
            lines.append("\n" + Fore.BLUE + "Protocol Distribution:" + Style.RESET_ALL)
            for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_packets * 100) if total_packets > 0 else 0
                lines.append(Fore.CYAN + f"  {protocol}: {count} packets ({percentage:.1f}%)" + Style.RESET_ALL)

        # IoT findings
        findings = data.get('iot_findings', [])
        if findings:
            lines.append("\n" + Fore.GREEN + f"IoT Protocol Findings ({len(findings)}):" + Style.RESET_ALL)
            for i, finding in enumerate(findings, 1):
                lines.append(Fore.GREEN + f"  {i}. {finding['protocol']} - {finding['details']}" + Style.RESET_ALL)
                if 'packet_info' in finding:
                    info = finding['packet_info']
                    if 'src_ip' in info and 'dst_ip' in info:
                        lines.append(Fore.YELLOW + f"     {info['src_ip']} -> {info['dst_ip']}" + Style.RESET_ALL)

        # Vulnerabilities
        vulnerabilities = data.get('vulnerabilities', [])
        if vulnerabilities:
            lines.append("\n" + Fore.RED + f"Vulnerabilities Found ({len(vulnerabilities)}):" + Style.RESET_ALL)
            for i, vuln in enumerate(vulnerabilities, 1):
                severity_color = {
                    'high': Fore.RED,
                    'medium': Fore.YELLOW,
                    'low': Fore.GREEN
                }.get(vuln.get('severity', 'medium'), Fore.YELLOW)

                lines.append(severity_color + f"  {i}. [{vuln.get('severity', 'unknown').upper()}] {vuln['vulnerability']}" + Style.RESET_ALL)
                lines.append(Fore.YELLOW + f"     {vuln['description']}" + Style.RESET_ALL)
                lines.append(Fore.CYAN + f"     Recommendation: {vuln['recommendation']}" + Style.RESET_ALL)

        # Empty results message
        if not findings and not vulnerabilities and total_packets == 0:
            lines.append(Fore.YELLOW + "No IoT traffic or vulnerabilities detected in captured packets." + Style.RESET_ALL)


def iotnet():
    """Main CLI entry point for iotnet."""
    parser = argparse.ArgumentParser(
        description="IoT network traffic analysis for protocol detection and vulnerability assessment."
    )

    # Input options - either pcap files or live capture
    parser.add_argument("pcap_files", nargs='*',
                       help="PCAP files to analyze")
    parser.add_argument("-i", "--interface",
                       help="Network interface for live capture (mutually exclusive with pcap files)")

    # Filtering options
    parser.add_argument("--ip", dest="ip_filter",
                       help="IP address to filter traffic (used as capture filter for live capture, display filter for pcaps)")

    # Live capture options
    parser.add_argument("-d", "--duration", type=int, default=30,
                       help="Live capture duration in seconds (default: 30)")
    parser.add_argument("-c", "--capture-filter",
                       help="Additional capture filter (BPF syntax for live capture)")

    # PCAP analysis options
    parser.add_argument("--display-filter",
                       help="Wireshark display filter for pcap analysis")
    parser.add_argument("--config",
                       help="Path to custom IoT detection rules configuration file")

    # Output options
    parser.add_argument("--format", choices=['text', 'json', 'quiet'], default='text',
                       help="Output format (default: text)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose output")

    args = parser.parse_args()
    init()  # Initialize colorama

    # Validate arguments
    if not args.pcap_files and not args.interface:
        parser.error("Either provide pcap file(s) or specify --interface for live capture")

    if args.pcap_files and args.interface:
        parser.error("Cannot specify both pcap files and --interface")

    # Set paths attribute for ConfigBuilder compatibility
    if args.pcap_files:
        args.paths = args.pcap_files

    # Build configuration
    config = ConfigBuilder.from_args(args, 'iotnet')

    # Add custom arguments
    config.custom_args.update({
        'ip_filter': getattr(args, 'ip_filter', None),
        'interface': getattr(args, 'interface', None),
        'duration': getattr(args, 'duration', 30),
        'capture_filter': getattr(args, 'capture_filter', None),
        'display_filter': getattr(args, 'display_filter', None),
        'config_path': getattr(args, 'config', None),
    })

    # Execute tool
    tool = IoTNetTool()
    result = tool.run(config)

    # Format and output result
    formatter = IoTNetOutputFormatter()
    output = formatter.format_result(result, config.output_format)
    if output:
        print(output)

    # Exit with appropriate code
    return 0 if result.success else 1
