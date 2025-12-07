#!/usr/bin/env python3
import argparse
from colorama import init, Fore, Style
from .core.ghidra_core import GhidraTool, DANGEROUS_FUNCTIONS
from .core.interfaces import ConfigBuilder, OutputFormatter


class GhidraOutputFormatter(OutputFormatter):
    """Custom output formatter for ghidra results."""

    def _format_text(self, result: 'ToolResult') -> str:
        """Format ghidra results as human-readable text."""
        if not result.success:
            return Fore.RED + "\n".join(result.errors) + Style.RESET_ALL

        if not result.data:
            return "No data available."

        lines = []
        data = result.data
        action = result.metadata.get('action', 'unknown')

        # Binary info header
        binary = data.get('binary', result.metadata.get('binary', ''))
        if binary:
            lines.append(Fore.BLUE + f"Binary: {binary}" + Style.RESET_ALL)

        # Program info
        prog_info = data.get('program_info', {})
        if prog_info:
            lines.append(Fore.CYAN + "Program Info:" + Style.RESET_ALL)
            lines.append(f"  Architecture: {prog_info.get('language', 'unknown')}")
            lines.append(f"  Format: {prog_info.get('executable_format', 'unknown')}")
            lines.append(f"  Image Base: {prog_info.get('image_base', 'unknown')}")

        # Summary stats
        summary = data.get('summary', {})
        if summary:
            lines.append("")
            lines.append(Fore.CYAN + "Summary:" + Style.RESET_ALL)
            lines.append(f"  Total Functions: {summary.get('total_functions', 0)}")
            lines.append(f"  Dangerous Function Calls: {summary.get('dangerous_function_count', 0)}")
            lines.append(f"  Total Strings: {summary.get('total_strings', 0)}")
            lines.append(f"  Imports: {summary.get('imports_count', 0)}")
            lines.append(f"  Exports: {summary.get('exports_count', 0)}")

        # Dangerous functions
        dangerous = data.get('dangerous_functions', data.get('top_dangerous_functions', []))
        if dangerous:
            lines.append("")
            lines.append(Fore.RED + "Dangerous Function Calls:" + Style.RESET_ALL)
            for func in dangerous[:15]:
                calls = func.get('dangerous_calls', [])
                calls_str = ', '.join(calls) if calls else 'unknown'
                lines.append(Fore.YELLOW + f"  {func['name']} @ {func['address']}" + Style.RESET_ALL)
                lines.append(Fore.RED + f"    Calls: {calls_str}" + Style.RESET_ALL)

        # Interesting strings
        interesting = data.get('interesting_strings', [])
        if interesting:
            lines.append("")
            lines.append(Fore.CYAN + "Interesting Strings:" + Style.RESET_ALL)
            for s in interesting[:20]:
                value = s['value'][:60] + '...' if len(s['value']) > 60 else s['value']
                lines.append(Fore.GREEN + f"  [{s['address']}] {value}" + Style.RESET_ALL)

        # Decompiled code
        decompiled = data.get('decompiled_c')
        if decompiled:
            lines.append("")
            lines.append(Fore.BLUE + f"Decompiled: {data.get('function_name', 'unknown')}" + Style.RESET_ALL)
            lines.append(Fore.CYAN + f"Signature: {data.get('signature', '')}" + Style.RESET_ALL)
            lines.append("")
            lines.append(decompiled)

        # Cross-references
        refs_to = data.get('references_to', [])
        refs_from = data.get('references_from', [])
        if refs_to or refs_from:
            lines.append("")
            lines.append(Fore.CYAN + f"Cross-References for {data.get('target', '')}:" + Style.RESET_ALL)
            if refs_to:
                lines.append(Fore.GREEN + f"  References TO ({len(refs_to)}):" + Style.RESET_ALL)
                for ref in refs_to[:10]:
                    lines.append(f"    {ref['from_address']} ({ref['ref_type']})")
            if refs_from:
                lines.append(Fore.YELLOW + f"  References FROM ({len(refs_from)}):" + Style.RESET_ALL)
                for ref in refs_from[:10]:
                    lines.append(f"    {ref['to_address']} ({ref['ref_type']})")

        # Priority review
        priority = data.get('priority_review', [])
        if priority:
            lines.append("")
            lines.append(Fore.RED + "Priority Review:" + Style.RESET_ALL)
            for func_name in priority:
                lines.append(f"  - {func_name}")

        # Execution time
        if result.execution_time > 0:
            lines.append("")
            lines.append(Fore.CYAN + f"Analysis time: {result.execution_time:.2f}s" + Style.RESET_ALL)

        return "\n".join(lines)


def ghidra():
    """Main CLI entry point for ghidra."""
    parser = argparse.ArgumentParser(
        description="Binary analysis and decompilation using Ghidra.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ghidra firmware.bin --action quick
  ghidra firmware.bin --action dangerous
  ghidra firmware.bin --action decompile --function main
  ghidra firmware.bin --action strings --pattern password
  ghidra firmware.bin --action xrefs --function strcpy
        """
    )
    parser.add_argument("binary", help="Binary file to analyze.")
    parser.add_argument("-a", "--action", required=True,
                        choices=['quick', 'analyze', 'dangerous', 'decompile', 'strings', 'xrefs'],
                        help="Analysis action to perform.")
    parser.add_argument("-f", "--function", help="Function name (for decompile, xrefs).")
    parser.add_argument("--address", help="Function address in hex (for decompile, xrefs).")
    parser.add_argument("-p", "--pattern", help="Search pattern for strings.")
    parser.add_argument("--ghidra-path", help="Path to Ghidra installation.")
    parser.add_argument("-o", "--output", help="Output file (default: stdout).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output.")
    parser.add_argument("--format", choices=['text', 'json', 'quiet'], default='text',
                        help="Output format (default: text)")

    args = parser.parse_args()
    init()  # Initialize colorama

    # Build configuration
    config = ConfigBuilder.from_args(args, 'ghidra')

    # Execute tool
    tool = GhidraTool()
    result = tool.run(config)

    # Format and output result
    formatter = GhidraOutputFormatter()
    output = formatter.format_result(result, config.output_format)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Results written to {args.output}")
    elif output:
        print(output)

    # Exit with appropriate code
    return 0 if result.success else 1
