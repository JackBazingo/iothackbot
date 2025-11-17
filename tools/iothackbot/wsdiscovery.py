import argparse
from colorama import init, Fore, Style
from .core.wsdiscovery_core import WSDiscoveryTool
from .core.interfaces import ConfigBuilder, OutputFormatter

class WSDiscoveryOutputFormatter(OutputFormatter):
    """Custom output formatter for wsdiscovery results."""

    def _format_text(self, result: 'ToolResult') -> str:
        """Format WS-Discovery results as human-readable text."""
        if not result.success:
            return "\n".join(result.errors)

        if not result.data:
            return "No discovery data available."

        data = result.data
        devices = data.get('devices', [])

        if not devices:
            return f"{Fore.YELLOW}No WS-Discovery devices found.{Style.RESET_ALL}"

        lines = []
        lines.append(f"\n{Fore.BLUE}DISCOVERY SUMMARY:{Style.RESET_ALL}")
        lines.append("=" * 60)

        for i, device in enumerate(devices, 1):
            lines.append(f"{Fore.CYAN}Device {i}:{Style.RESET_ALL}")
            lines.append(f"  {Fore.GREEN}IP Address:{Style.RESET_ALL} {device['ip']}:{device['port']}")

            if 'endpoint_reference' in device:
                lines.append(f"  {Fore.GREEN}Endpoint Reference:{Style.RESET_ALL} {device['endpoint_reference']}")

            if 'types' in device:
                lines.append(f"  {Fore.GREEN}Device Types:{Style.RESET_ALL} {device['types']}")

            if 'scopes' in device:
                scopes = device['scopes']
                lines.append(f"  {Fore.GREEN}Device Information:{Style.RESET_ALL}")
                for scope in scopes.split():
                    if ':' in scope and 'onvif://' in scope:
                        key, value = scope.split(':', 1)
                        if 'manufacturer' in key:
                            lines.append(f"    Manufacturer: {value}")
                        elif 'name' in key:
                            lines.append(f"    Name: {value}")
                        elif 'hardware' in key:
                            lines.append(f"    Hardware: {value}")
                        elif 'serial' in key:
                            lines.append(f"    Serial: {value}")
                        elif 'version' in key:
                            lines.append(f"    Version: {value}")
                        elif 'location' in key:
                            lines.append(f"    Location: {value}")

            if 'xaddrs' in device:
                xaddrs = device['xaddrs'].split()
                lines.append(f"  {Fore.GREEN}Service Endpoints:{Style.RESET_ALL}")
                for xaddr in xaddrs:
                    lines.append(f"    {Fore.CYAN}•{Style.RESET_ALL} {xaddr}")

            if 'metadata_version' in device:
                lines.append(f"  {Fore.GREEN}Metadata Version:{Style.RESET_ALL} {device['metadata_version']}")

            lines.append("")

        lines.append(f"{Fore.BLUE}Total unique devices discovered: {len(devices)}{Style.RESET_ALL}")
        lines.append(f"{Fore.BLUE}WS-Discovery scan completed.{Style.RESET_ALL}")

        return "\n".join(lines)


def wsdiscovery():
    """Main CLI entry point for wsdiscovery."""
    parser = argparse.ArgumentParser(description="WS-Discovery Fuzzer for ONVIF-like devices")
    parser.add_argument("hostname", help="Hostname or IP address to target")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full XML responses")
    parser.add_argument("--format", choices=['text', 'json', 'quiet'], default='text',
                       help="Output format (default: text)")

    args = parser.parse_args()
    init()  # Initialize colorama

    # Build configuration
    config = ConfigBuilder.from_args(args, 'wsdiscovery')

    # Execute tool
    tool = WSDiscoveryTool()
    result = tool.run(config)

    # Format and output result
    formatter = WSDiscoveryOutputFormatter()
    output = formatter.format_result(result, config.output_format)
    if output:
        print(output)

    # Exit with appropriate code
    return 0 if result.success else 1
