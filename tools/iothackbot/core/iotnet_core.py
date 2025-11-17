"""
Core iotnet functionality - IoT network traffic analysis.
Separated from CLI logic for automation and chaining.
"""

import os
import time
import json
import re
from typing import List, Dict, Any, Optional
from .interfaces import ToolInterface, ToolConfig, ToolResult

try:
    import pyshark
    HAS_PYSHARK = True
except ImportError:
    HAS_PYSHARK = False


class IoTNetAnalyzer:
    """IoT network traffic analyzer using PyShark."""

    def __init__(self, ip_filter: Optional[str] = None, config_path: Optional[str] = None):
        """
        Initialize the analyzer.

        Args:
            ip_filter: Optional IP address to filter traffic
            config_path: Path to detection rules config file
        """
        self.ip_filter = ip_filter
        self.config = self._load_config(config_path)

    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Load IoT detection rules from configuration file.

        Args:
            config_path: Path to config file, uses default if None

        Returns:
            Configuration dictionary
        """
        if config_path is None:
            # Use default config path
            config_path = os.path.join(
                os.path.dirname(__file__),
                '../../../config/iot/detection_rules.json'
            )
            config_path = os.path.abspath(config_path)

        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            return config
        except (FileNotFoundError, json.JSONDecodeError) as e:
            # Fall back to minimal default config
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Get minimal default configuration if config file is not available."""
        return {
            "protocols": {},
            "vulnerabilities": {},
            "user_agents": {"iot_devices": [], "iot_libraries": []},
            "known_vulnerable_endpoints": [],
            "severity_levels": {"critical": 9, "high": 7, "medium": 5, "low": 3, "info": 1}
        }

    def analyze_pcap(self, pcap_path: str, display_filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze a pcap file for IoT traffic.

        Args:
            pcap_path: Path to pcap file
            display_filter: Optional Wireshark display filter

        Returns:
            Analysis results dictionary
        """
        if not HAS_PYSHARK:
            raise ImportError("PyShark is required for IoT network analysis")

        results = {
            'total_packets': 0,
            'protocols': {},
            'iot_findings': [],
            'vulnerabilities': [],
            'traffic_summary': {}
        }

        try:
            # Create display filter for IP if specified
            filter_str = display_filter or ""
            if self.ip_filter:
                ip_condition = f"ip.addr == {self.ip_filter}"
                filter_str = ip_condition if not filter_str else f"({filter_str}) and ({ip_condition})"

            # Read pcap file
            capture = pyshark.FileCapture(pcap_path, display_filter=filter_str)

            for packet in capture:
                results['total_packets'] += 1
                self._analyze_packet(packet, results)

        except Exception as e:
            raise RuntimeError(f"Error analyzing pcap file: {e}")

        return results

    def live_capture(self, interface: str, duration: int = 30,
                    capture_filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform live network capture for IoT traffic analysis.

        Args:
            interface: Network interface to capture on
            duration: Capture duration in seconds
            capture_filter: Optional capture filter

        Returns:
            Analysis results dictionary
        """
        if not HAS_PYSHARK:
            raise ImportError("PyShark is required for IoT network analysis")

        results = {
            'total_packets': 0,
            'protocols': {},
            'iot_findings': [],
            'vulnerabilities': [],
            'traffic_summary': {},
            'capture_duration': duration,
            'interface': interface
        }

        try:
            # Create capture filter for IP if specified
            filter_str = capture_filter or ""
            if self.ip_filter:
                ip_condition = f"host {self.ip_filter}"
                filter_str = ip_condition if not filter_str else f"{filter_str} and {ip_condition}"

            # Start live capture
            capture = pyshark.LiveCapture(interface=interface, bpf_filter=filter_str)

            # Note: Progress messages removed to support JSON output mode
            # Live capture will run silently for specified duration
            capture.sniff(timeout=duration)

            for packet in capture:
                results['total_packets'] += 1
                self._analyze_packet(packet, results)

        except Exception as e:
            raise RuntimeError(f"Error during live capture: {e}")

        return results

    def _analyze_packet(self, packet, results: Dict[str, Any]) -> None:
        """
        Analyze a single packet for IoT protocols and vulnerabilities.

        Args:
            packet: PyShark packet object
            results: Results dictionary to update
        """
        # Track protocol usage
        if hasattr(packet, 'transport_layer'):
            protocol = packet.transport_layer
            results['protocols'][protocol] = results['protocols'].get(protocol, 0) + 1

        # IoT protocol detection and analysis
        findings = self._detect_iot_protocols(packet)
        if findings:
            results['iot_findings'].extend(findings)

        # Vulnerability checks
        vulns = self._check_vulnerabilities(packet)
        if vulns:
            results['vulnerabilities'].extend(vulns)

    def _detect_iot_protocols(self, packet) -> List[Dict[str, Any]]:
        """
        Detect IoT-specific protocols in packet using configuration rules.

        Args:
            packet: PyShark packet object

        Returns:
            List of protocol detection findings
        """
        findings = []

        try:
            # Check each configured protocol
            for protocol_key, protocol_config in self.config.get('protocols', {}).items():
                protocol_findings = self._check_protocol_rules(packet, protocol_key, protocol_config)
                findings.extend(protocol_findings)

        except AttributeError:
            # Skip packets that don't have expected attributes
            pass

        return findings

    def _check_protocol_rules(self, packet, protocol_key: str, protocol_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check packet against protocol-specific detection rules.

        Args:
            packet: PyShark packet object
            protocol_key: Protocol identifier
            protocol_config: Protocol configuration

        Returns:
            List of protocol detection findings
        """
        findings = []

        for rule in protocol_config.get('detection_rules', []):
            rule_type = rule.get('type')

            if rule_type == 'port':
                # Port-based detection
                if self._check_port_rule(packet, rule):
                    finding = {
                        'protocol': protocol_config['name'],
                        'type': 'protocol_detection',
                        'details': rule.get('description', f'{protocol_config["name"]} traffic detected'),
                        'packet_info': self._extract_packet_info(packet)
                    }
                    findings.append(finding)

            elif rule_type == 'user_agent':
                # User agent pattern detection
                if self._check_user_agent_rule(packet, rule):
                    finding = {
                        'protocol': protocol_config['name'],
                        'type': 'protocol_detection',
                        'details': rule.get('description', f'IoT user agent detected'),
                        'packet_info': self._extract_packet_info(packet)
                    }
                    if hasattr(packet, 'http') and hasattr(packet.http, 'user_agent'):
                        finding['packet_info']['user_agent'] = packet.http.user_agent
                    findings.append(finding)

            elif rule_type == 'payload_pattern':
                # Payload pattern detection
                if self._check_payload_rule(packet, rule):
                    finding = {
                        'protocol': protocol_config['name'],
                        'type': 'protocol_detection',
                        'details': rule.get('description', f'{protocol_config["name"]} payload pattern detected'),
                        'packet_info': self._extract_packet_info(packet)
                    }
                    findings.append(finding)

        return findings

    def _check_port_rule(self, packet, rule: Dict[str, Any]) -> bool:
        """Check if packet matches port-based rule."""
        if hasattr(packet, 'tcp'):
            tcp_ports = rule.get('tcp_ports', [])
            if packet.tcp.dstport in [str(port) for port in tcp_ports]:
                return True
            if packet.tcp.srcport in [str(port) for port in tcp_ports]:
                return True

        if hasattr(packet, 'udp'):
            udp_ports = rule.get('udp_ports', [])
            if packet.udp.dstport in [str(port) for port in udp_ports]:
                return True
            if packet.udp.srcport in [str(port) for port in udp_ports]:
                return True

        return False

    def _check_user_agent_rule(self, packet, rule: Dict[str, Any]) -> bool:
        """Check if packet matches user agent rule."""
        if not (hasattr(packet, 'http') and hasattr(packet.http, 'user_agent')):
            return False

        user_agent = packet.http.user_agent
        patterns = rule.get('patterns', [])
        case_insensitive = rule.get('case_insensitive', True)

        flags = re.IGNORECASE if case_insensitive else 0

        for pattern in patterns:
            if re.search(pattern, user_agent, flags):
                return True

        return False

    def _check_payload_rule(self, packet, rule: Dict[str, Any]) -> bool:
        """Check if packet payload matches pattern."""
        # This is a simplified implementation - in practice, you'd need to access packet payload
        # PyShark makes this complex, so for now we'll return False
        # A more complete implementation would decode packet layers to access payload
        return False

    def _extract_packet_info(self, packet) -> Dict[str, Any]:
        """Extract basic packet information."""
        info = {}

        if hasattr(packet, 'ip'):
            info['src_ip'] = packet.ip.src
            info['dst_ip'] = packet.ip.dst

        if hasattr(packet, 'tcp'):
            info['src_port'] = packet.tcp.srcport
            info['dst_port'] = packet.tcp.dstport
            info['protocol'] = 'TCP'

        elif hasattr(packet, 'udp'):
            info['src_port'] = packet.udp.srcport
            info['dst_port'] = packet.udp.dstport
            info['protocol'] = 'UDP'

        return info

    def _check_vulnerabilities(self, packet) -> List[Dict[str, Any]]:
        """
        Check packet for known IoT vulnerabilities using configuration rules.

        Args:
            packet: PyShark packet object

        Returns:
            List of vulnerability findings
        """
        vulnerabilities = []

        try:
            # Check each configured vulnerability
            for vuln_key, vuln_config in self.config.get('vulnerabilities', {}).items():
                vuln_findings = self._check_vulnerability_rules(packet, vuln_key, vuln_config)
                vulnerabilities.extend(vuln_findings)

        except AttributeError:
            # Skip packets that don't have expected attributes
            pass

        return vulnerabilities

    def _check_vulnerability_rules(self, packet, vuln_key: str, vuln_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check packet against vulnerability-specific rules.

        Args:
            packet: PyShark packet object
            vuln_key: Vulnerability identifier
            vuln_config: Vulnerability configuration

        Returns:
            List of vulnerability findings
        """
        findings = []

        for rule in vuln_config.get('rules', []):
            if self._evaluate_vulnerability_rule(packet, rule):
                finding = {
                    'vulnerability': vuln_config['name'],
                    'severity': vuln_config.get('severity', 'medium'),
                    'description': vuln_config.get('description', ''),
                    'recommendation': vuln_config.get('recommendation', ''),
                    'packet_info': self._extract_packet_info(packet)
                }

                # Add additional context based on vulnerability type
                if vuln_key == 'suspicious_endpoint' and hasattr(packet, 'http'):
                    if hasattr(packet.http, 'request_uri'):
                        finding['packet_info']['uri'] = packet.http.request_uri
                    if hasattr(packet.http, 'request_method'):
                        finding['packet_info']['method'] = packet.http.request_method

                findings.append(finding)
                break  # Only report each vulnerability once per packet

        return findings

    def _evaluate_vulnerability_rule(self, packet, rule: Dict[str, Any]) -> bool:
        """
        Evaluate a vulnerability rule condition.

        Args:
            packet: PyShark packet object
            rule: Rule configuration

        Returns:
            True if rule matches, False otherwise
        """
        condition = rule.get('condition', '')

        # Simple condition evaluation - can be extended for more complex logic
        if 'port ==' in condition:
            port_value = condition.split('port ==')[1].strip()
            if hasattr(packet, 'tcp') and packet.tcp.dstport == port_value.strip("'\""):
                return True
            if hasattr(packet, 'udp') and packet.udp.dstport == port_value.strip("'\""):
                return True

        elif 'endpoint matches' in condition:
            if hasattr(packet, 'http') and hasattr(packet.http, 'request_uri'):
                uri = packet.http.request_uri.lower()
                patterns = condition.split('endpoint matches')[1].strip().split('|')
                for pattern in patterns:
                    if pattern.strip().strip("'\"") in uri:
                        return True

        elif 'authorization_header contains' in condition:
            if hasattr(packet, 'http') and hasattr(packet.http, 'authorization'):
                auth = packet.http.authorization.lower()
                patterns = condition.split('authorization_header contains')[1].strip().split('|')
                for pattern in patterns:
                    if pattern.strip().strip("'\"") in auth:
                        return True

        # For more complex rules, you could implement a simple expression evaluator
        # For now, return False for unsupported conditions
        return False


class IoTNetTool(ToolInterface):
    """IoT Network Analysis tool implementation."""

    @property
    def name(self) -> str:
        return "iotnet"

    @property
    def description(self) -> str:
        return "IoT network traffic analysis for protocol detection and vulnerability assessment"

    def run(self, config: ToolConfig) -> ToolResult:
        """Execute IoT network analysis."""
        start_time = time.time()

        try:
            # Extract custom arguments
            ip_filter = config.custom_args.get('ip_filter')
            interface = config.custom_args.get('interface')
            duration = config.custom_args.get('duration', 30)
            capture_filter = config.custom_args.get('capture_filter')
            display_filter = config.custom_args.get('display_filter')
            config_path = config.custom_args.get('config_path')

            # Initialize analyzer
            analyzer = IoTNetAnalyzer(ip_filter=ip_filter, config_path=config_path)

            results = {}

            # Process input paths (pcap files)
            if config.input_paths:
                for input_path in config.input_paths:
                    if os.path.isfile(input_path) and input_path.endswith(('.pcap', '.pcapng')):
                        # Only print progress in verbose or text mode
                        if config.output_format == 'text' or config.verbose:
                            print(f"Analyzing pcap file: {input_path}")
                        file_results = analyzer.analyze_pcap(input_path, display_filter)
                        results[input_path] = file_results
                    else:
                        return ToolResult(
                            success=False,
                            data=None,
                            errors=[f"Invalid input: {input_path}. Expected pcap file."],
                            metadata={},
                            execution_time=time.time() - start_time
                        )
            # Perform live capture if interface specified
            elif interface:
                results = analyzer.live_capture(interface, duration, capture_filter)
            else:
                return ToolResult(
                    success=False,
                    data=None,
                    errors=["Either provide pcap file(s) or specify --interface for live capture"],
                    metadata={},
                    execution_time=time.time() - start_time
                )

            execution_time = time.time() - start_time

            return ToolResult(
                success=True,
                data=results,
                errors=[],
                metadata={
                    'ip_filter': ip_filter,
                    'interface': interface,
                    'duration': duration,
                    'total_packets_analyzed': sum(r.get('total_packets', 0) for r in (results.values() if isinstance(results, dict) and not interface else [results]))
                },
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = time.time() - start_time
            return ToolResult(
                success=False,
                data=None,
                errors=[str(e)],
                metadata={},
                execution_time=execution_time
            )
