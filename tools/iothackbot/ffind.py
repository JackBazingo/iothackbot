#!/usr/bin/env python3
import argparse
from colorama import init, Fore, Style
from .core.ffind_core import FfindTool, ARTIFACT_FILES
from .core.interfaces import ConfigBuilder, OutputFormatter

class FfindOutputFormatter(OutputFormatter):
    """Custom output formatter for ffind results."""

    def _format_text(self, result: 'ToolResult') -> str:
        """Format ffind results as human-readable text."""
        if not result.success:
            return "\n".join(result.errors)

        if not result.data:
            return "No data available."

        lines = []

        # Show extraction directory if applicable
        extract_dir = result.metadata.get('extraction_dir')
        if extract_dir:
            lines.append(Fore.YELLOW + f"All extractions will be in: {extract_dir}" + Style.RESET_ALL)

        type_dict = result.data.get('type_summary', {})
        if type_dict:
            lines.append("\n" + Fore.BLUE + "Type Summary:" + Style.RESET_ALL)
            # Show artifact types by default, but could be configurable
            types_to_show = sorted(type_dict.keys())
            for typ in types_to_show:
                files_info = type_dict[typ]
                count = len(files_info)
                lines.append(Fore.CYAN + f"{typ}: {count} files" + Style.RESET_ALL)
                for file_info in sorted(files_info, key=lambda x: x['path']):
                    description = file_info['description']
                    path = file_info['path']
                    lines.append(Fore.CYAN + f"\t- {path}" + Style.RESET_ALL)
                    lines.append(Fore.YELLOW + f"\t  {description}" + Style.RESET_ALL)

        # Show extraction summary
        extracted_count = result.metadata.get('extracted_count', 0)
        if extracted_count > 0:
            lines.append(Fore.GREEN + f"\nSuccessfully extracted {extracted_count} files" + Style.RESET_ALL)

        return "\n".join(lines)


def ffind():
    """Main CLI entry point for ffind."""
    parser = argparse.ArgumentParser(description="File finder with type analysis and optional extraction.")
    parser.add_argument("paths", nargs='+', help="File or directory paths to process.")
    parser.add_argument("-e", "--extract", action="store_true", help="Perform extractions on supported file types.")
    parser.add_argument("-d", "--directory", help="Custom extraction directory (default: timestamped in /tmp).", default=None)
    parser.add_argument("-a", "--all", action="store_true", help="Print summary for all file types (default: only artifact types).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print detailed file types for each file.")
    parser.add_argument("--format", choices=['text', 'json', 'quiet'], default='text',
                       help="Output format (default: text)")

    args = parser.parse_args()
    init()  # Initialize colorama

    # Build configuration
    config = ConfigBuilder.from_args(args, 'ffind')

    # Execute tool
    tool = FfindTool()
    result = tool.run(config)

    # Format and output result
    formatter = FfindOutputFormatter()
    output = formatter.format_result(result, config.output_format)
    if output:
        print(output)

    # Exit with appropriate code
    return 0 if result.success else 1
