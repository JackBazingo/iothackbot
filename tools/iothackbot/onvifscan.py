#!/usr/bin/env python3
import argparse
from colorama import init, Fore, Style
from .core.onvifscan_core import OnvifScanTool
from .core.interfaces import ConfigBuilder, OutputFormatter, ToolConfig, ToolResult

class OnvifScanOutputFormatter(OutputFormatter):
    """Custom output formatter for onvifscan results."""

    def __init__(self, verbose=False):
        self.verbose = verbose

    def format_result(self, result: 'ToolResult', format_type: str) -> str:
        """Override to handle verbose output."""
        if format_type == 'json':
            return self._format_json(result)
        elif format_type == 'text':
            return self._format_text(result)
        elif format_type == 'quiet':
            return self._format_quiet(result)
        else:
            return self._format_text(result)

    def _format_text(self, result: 'ToolResult') -> str:
        """Format onvifscan results as human-readable text."""
        if not result.success:
            return "\n".join(result.errors)

        if not result.data:
            return "No scan data available."

        lines = []
        data = result.data

        # Check if this is an auth scan result (has security_issues) or other result
        if 'security_issues' in data:
            # Auth scan result
            mode = "comprehensive" if result.metadata.get('test_all', False) else "standard"
            lines.append(Fore.BLUE + f"ONVIF unauthenticated access test completed ({mode} mode)" + Fore.RESET)
            lines.append(Fore.CYAN + f"Target: {result.metadata.get('target_url', 'Unknown')}" + Fore.RESET)
            lines.append("")

            # Security issues summary
            security_issues = data.get('security_issues', [])
            if security_issues:
                lines.append(Fore.RED + f"SECURITY ISSUES FOUND: {len(security_issues)}" + Fore.RESET)
                for issue in security_issues:
                    lines.append(Fore.RED + f"  - {issue['name']}: {issue['result']}" + Fore.RESET)
                lines.append("")

            # Results by status code
            lines.append(Fore.BLUE + "SUMMARY BY RESPONSE CODE:" + Fore.RESET)
            lines.append("=" * 60)

            results_by_status = data.get('results_by_status', {})
            all_results = data.get('all_results', [])

            # Sort status codes
            def sort_key(code):
                if code == "SKIPPED":
                    return -1
                elif code == "ERROR":
                    return 999
                elif isinstance(code, int):
                    return code
                else:
                    return 1000

            sorted_codes = sorted(results_by_status.keys(), key=sort_key)

            for status_code in sorted_codes:
                requests_for_code = results_by_status[status_code]
                lines.append(Fore.CYAN + f"Status {status_code}: {len(requests_for_code)} requests" + Fore.RESET)

                for result_item in sorted(requests_for_code, key=lambda x: x["name"]):
                    # Color based on result type
                    if result_item.get("security_issue", False):
                        color = Fore.RED
                    elif "secure" in result_item["result"] or "unauthenticated by design" in result_item["result"]:
                        color = Fore.GREEN
                    else:
                        color = Fore.YELLOW

                    auth_indicator = "[AUTH]" if result_item["auth_required"] else "[OPEN]"
                    lines.append(f"  {color}{auth_indicator} {result_item['name']}: {result_item['result']}{Fore.RESET}")

                    # Add verbose output - full response content
                    if self.verbose and "response_content" in result_item and result_item["response_content"]:
                        lines.append(Fore.MAGENTA + f"    Response Content:" + Fore.RESET)
                        # Split responses for readability (no truncation in verbose mode)
                        content = result_item["response_content"]
                        lines.extend([f"    {line}" for line in content.split('\n') if line.strip()])
                        lines.append("")

                lines.append("")
        else:
            # Other scan results (brute)
            scan_type = result.metadata.get('scan_type', 'unknown')
            lines.append(Fore.BLUE + f"ONVIF {scan_type} scan completed" + Fore.RESET)
            lines.append(Fore.CYAN + f"Target: {result.metadata.get('target_url', result.metadata.get('input_path', 'Unknown'))}" + Fore.RESET)
            lines.append("")

            # Display results based on type
            if 'brute_results' in data:
                lines.append(Fore.YELLOW + "BRUTE FORCE RESULTS:" + Fore.RESET)
                lines.append(data['brute_results'])

            lines.append("")

        return "\n".join(lines)

    def _format_json(self, result: 'ToolResult') -> str:
        """Format onvifscan results as JSON."""
        import json
        return json.dumps(result.data, indent=2, default=str)

    def _format_quiet(self, result: 'ToolResult') -> str:
        """Quiet output - just security issues."""
        if not result.success:
            return ""

        data = result.data
        security_issues = data.get('security_issues', [])
        if security_issues:
            lines = [f"SECURITY ISSUE: {issue['name']} - {issue['result']}" for issue in security_issues]
            return "\n".join(lines)
        return ""


def run_auth_scan(config: 'ToolConfig') -> 'ToolResult':
    """Run the authentication scan (existing functionality)."""
    tool = OnvifScanTool()
    return tool.run(config)

def run_brute(config: 'ToolConfig') -> 'ToolResult':
    """Run credential brute-forcing on auth-required endpoints."""
    import os
    import time
    import requests

    # Load wordlists
    wordlists_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'wordlists')
    usernames_file = config.custom_args.get('usernames_file', os.path.join(wordlists_dir, 'onvif-usernames.txt'))
    passwords_file = config.custom_args.get('passwords_file', os.path.join(wordlists_dir, 'onvif-passwords.txt'))

    if not os.path.exists(usernames_file) or not os.path.exists(passwords_file):
        return ToolResult(
            success=False,
            data={},
            errors=["Wordlist files not found"],
            metadata={"scan_type": "brute force", "target_url": config.input_path}
        )

    with open(usernames_file, 'r') as f:
        usernames = [line.strip() for line in f if line.strip()]
    with open(passwords_file, 'r') as f:
        passwords = [line.strip() for line in f if line.strip()]

    # First run auth scan to find endpoints requiring authentication
    auth_result = run_auth_scan(config)
    if not auth_result.success or 'all_results' not in auth_result.data:
        return ToolResult(
            success=False,
            data={},
            errors=["Failed to run authentication scan"],
            metadata={"scan_type": "brute force", "target_url": config.input_path}
        )

    # Find endpoints that require auth (401 responses)
    auth_required_endpoints = []
    for result in auth_result.data['all_results']:
        if result.get('status_code') == 401 and result.get('endpoint'):
            auth_required_endpoints.append(result['endpoint'])

    if not auth_required_endpoints:
        return ToolResult(
            success=True,
            data={"brute_results": "No endpoints requiring authentication found"},
            metadata={"scan_type": "brute force", "target_url": config.input_path, "tested_endpoints": 0}
        )

    # Brute force each endpoint
    successful_logins = []
    tested_combinations = 0
    max_attempts = 20  # Reduce limit to prevent overwhelming device

    for endpoint in auth_required_endpoints[:1]:  # Test only first endpoint to reduce load
        for username in usernames[:5]:  # Limit usernames for safety
            for password in passwords[:5]:  # Limit passwords for safety
                if tested_combinations >= max_attempts:
                    break

                # Try Digest first (more common for ONVIF), then Basic
                for auth_method in ['digest', 'basic']:
                    if tested_combinations >= max_attempts:
                        break

                    try:
                        if auth_method == 'basic':
                            auth = requests.auth.HTTPBasicAuth(username, password)
                        else:
                            auth = requests.auth.HTTPDigestAuth(username, password)

                        # Send a basic GetDeviceInformation request (works on most ONVIF endpoints)
                        soap_body = '''<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>'''

                        response = requests.post(
                            endpoint,
                            auth=auth,
                            data=soap_body,
                            timeout=5,
                            headers={"Content-Type": "application/soap+xml; charset=utf-8"}
                        )

                        tested_combinations += 1

                        if response.status_code == 200:
                            successful_logins.append({
                                "endpoint": endpoint,
                                "username": username,
                                "password": password,
                                "auth_method": auth_method
                            })
                            break  # Found working creds, no need to try other method

                        # Delay to prevent overwhelming the device
                        time.sleep(0.5)

                    except requests.RequestException:
                        continue

            if tested_combinations >= max_attempts:
                break
        if tested_combinations >= max_attempts:
            break

    result_message = f"Tested {tested_combinations} credential combinations (with Basic/Digest auth) on {len(auth_required_endpoints)} endpoints"
    if successful_logins:
        result_message += f"\nSUCCESSFUL LOGINS FOUND: {len(successful_logins)}"
        for login in successful_logins:
            result_message += f"\n  - {login['endpoint']}: {login['username']}:{login['password']} ({login['auth_method']} auth)"
    else:
        result_message += "\nNo successful logins found"

    return ToolResult(
        success=True,
        data={"brute_results": result_message, "successful_logins": successful_logins},
        metadata={
            "scan_type": "brute force",
            "target_url": config.input_path,
            "tested_endpoints": len(auth_required_endpoints),
            "tested_combinations": tested_combinations,
            "successful_logins": len(successful_logins)
        }
    )

def onvifscan():
    """Main CLI entry point with subcommands."""
    parser = argparse.ArgumentParser(description="ONVIF Security Scanner")
    subparsers = parser.add_subparsers(dest='command', required=True, help="Available commands")

    # Auth subcommand (existing functionality)
    auth_parser = subparsers.add_parser('auth', help="Run authentication checks")
    auth_parser.add_argument("url", help="Base URL of the ONVIF device")
    auth_parser.add_argument("-v", "--verbose", action="store_true", help="Show full response content")
    auth_parser.add_argument("-a", "--all", action="store_true", help="Test all endpoints including destructive")
    auth_parser.add_argument("--format", choices=['text', 'json', 'quiet'], default='text', help="Output format")

    # Brute subcommand
    brute_parser = subparsers.add_parser('brute', help="Run credential brute-forcing")
    brute_parser.add_argument("url", help="Base URL of the ONVIF device")
    brute_parser.add_argument("--usernames", help="Path to usernames wordlist (default: built-in onvif-usernames.txt)")
    brute_parser.add_argument("--passwords", help="Path to passwords wordlist (default: built-in onvif-passwords.txt)")
    brute_parser.add_argument("--format", choices=['text', 'json', 'quiet'], default='text', help="Output format")

    args = parser.parse_args()
    init()  # Initialize colorama

    # Normalize URL - prepend http:// if no scheme is provided
    url = args.url
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    
    # Build base config
    config = ToolConfig(
        input_paths=[url],
        output_format=args.format,
        verbose=getattr(args, 'verbose', False),
        custom_args={'all': getattr(args, 'all', False)}
    )

    # Execute based on subcommand
    if args.command == 'auth':
        result = run_auth_scan(config)
    elif args.command == 'brute':
        if hasattr(args, 'usernames') and args.usernames:
            config.custom_args['usernames_file'] = args.usernames
        if hasattr(args, 'passwords') and args.passwords:
            config.custom_args['passwords_file'] = args.passwords
        result = run_brute(config)
    else:
        parser.print_help()
        return 1

    # Format and output result
    formatter = OnvifScanOutputFormatter(verbose=config.verbose)
    output = formatter.format_result(result, config.output_format)
    if output:
        print(output)

    return 0 if result.success else 1
