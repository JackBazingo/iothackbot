"""
Core wsdiscovery functionality - WS-Discovery protocol scanning and device detection.
Separated from CLI logic for automation and chaining.
"""

import socket
import time
import struct
import uuid
import xml.dom.minidom
import threading
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple, Any, Optional


def send_message(target_ip: str, xml_template: str, timeout: float = 5, response_multicast: bool = True,
                thread_id: int = 0, verbose: bool = False) -> List[Tuple[Tuple[str, int], bytes]]:
    """
    Send a WS-Discovery message and listen for responses.
    Returns list of (address, response_data) tuples.
    """
    multicast_group = '239.255.255.250'
    message_id = f"urn:uuid:{uuid.uuid4()}"

    # Replace placeholders in template
    message_xml = xml_template.format(message_id=message_id)
    message = message_xml.encode('utf-8')

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Enable broadcast if target is broadcast address
    if target_ip == '255.255.255.255' or target_ip == '<broadcast>':
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Determine if we need to bind to 3702 and join multicast
    bind_port = 3702 if target_ip.startswith('239.') or response_multicast else 0
    try:
        sock.bind(('', bind_port))
    except OSError:
        return []

    # Join multicast group if target is multicast or response_multicast is True
    if target_ip.startswith('239.') or response_multicast:
        mreq = struct.pack("4sl", socket.inet_aton(multicast_group), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    # Send the message
    try:
        sock.sendto(message, (target_ip, 3702))
    except (socket.gaierror, OSError):
        sock.close()
        return []

    # Set timeout for receiving
    sock.settimeout(1)

    # Listen for responses
    responses = []
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            data, addr = sock.recvfrom(4096)
            responses.append((addr, data))
        except socket.timeout:
            continue
        except OSError:
            break

    sock.close()
    return responses


def fuzz_ws_discovery(target_ip: str, timeout: float = 5, response_multicast: bool = True,
                     verbose: bool = False, parallel: bool = True) -> List[Tuple[Tuple[str, int], bytes]]:
    """
    Send various WS-Discovery messages to fuzz device implementations.
    Returns all responses received.
    """
    # WS-Discovery 1.0 Probe (generic)
    probe_10 = '''<?xml version="1.0" encoding="UTF-8"?>
<soap-env:Envelope xmlns:soap-env="http://www.w3.org/2003/05/soap-envelope"
                   xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <soap-env:Header>
    <a:Action mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
    <a:MessageID>{message_id}</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <a:To mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
  </soap-env:Header>
  <soap-env:Body>
    <Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery" />
  </soap-env:Body>
</soap-env:Envelope>'''

    # WS-Discovery 1.0 Probe with ONVIF Types
    probe_10_onvif_types = '''<?xml version="1.0" encoding="UTF-8"?>
<soap-env:Envelope xmlns:soap-env="http://www.w3.org/2003/05/soap-envelope"
                   xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <soap-env:Header>
    <a:Action mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
    <a:MessageID>{message_id}</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:ReplyTo>
    <a:To mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
  </soap-env:Header>
  <soap-env:Body>
    <Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <Types>dn:NetworkVideoTransmitter</Types>
    </Probe>
  </soap-env:Body>
</soap-env:Envelope>'''

    # Hello message (announcement)
    hello = '''<?xml version="1.0" encoding="UTF-8"?>
<soap-env:Envelope xmlns:soap-env="http://www.w3.org/2003/05/soap-envelope"
                   xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <soap-env:Header>
    <a:Action mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</a:Action>
    <a:MessageID>{message_id}</a:MessageID>
    <a:From>
      <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
    </a:From>
    <a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
  </soap-env:Header>
  <soap-env:Body>
    <Hello xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <EndpointReference>
        <a:Address>{message_id}</a:Address>
      </EndpointReference>
      <Types>dn:NetworkVideoTransmitter</Types>
      <Scopes>onvif://www.onvif.org</Scopes>
      <XAddrs>http://example.com</XAddrs>
      <MetadataVersion>1</MetadataVersion>
    </Hello>
  </soap-env:Body>
</soap-env:Envelope>'''

    # List of messages to send
    messages = [
        ("WS-Discovery 1.0 Probe", probe_10),
        ("WS-Discovery 1.0 Probe with ONVIF Types", probe_10_onvif_types),
        ("Hello Announcement", hello),
    ]

    all_responses = []

    if parallel:
        threads = []
        for i, (name, xml) in enumerate(messages):
            t = threading.Thread(
                target=lambda n=name, x=xml, tid=i: all_responses.extend(
                    send_message(target_ip, x, timeout, response_multicast, tid, verbose)
                ),
                name=f"Fuzz-{i}"
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join()
    else:
        for i, (name, xml) in enumerate(messages):
            responses = send_message(target_ip, xml, timeout, response_multicast, thread_id=i, verbose=verbose)
            all_responses.extend(responses)

    return all_responses


def parse_ws_discovery_response(response_data: bytes) -> Dict[str, Any]:
    """Parse WS-Discovery response XML and extract device information."""
    try:
        response_str = response_data.decode('utf-8', errors='ignore')
        root = ET.fromstring(response_str)

        # Handle different namespaces
        ns = {
            'soap': 'http://www.w3.org/2003/05/soap-envelope',
            'wsa': 'http://www.w3.org/2005/08/addressing',
            'd': 'http://schemas.xmlsoap.org/ws/2005/04/discovery',
            'tns': 'http://schemas.xmlsoap.org/ws/2005/04/discovery'
        }

        device_info = {}

        # Look for ProbeMatches
        probe_matches = (root.findall('.//d:ProbeMatches/d:ProbeMatch', ns) or
                        root.findall('.//tns:ProbeMatches/tns:ProbeMatch', ns))
        for probe_match in probe_matches:
            # Endpoint Reference
            epr = (probe_match.find('.//wsa:Address', ns) or
                  probe_match.find('wsa:EndpointReference/wsa:Address', ns))
            if epr is not None:
                device_info['endpoint_reference'] = epr.text

            # Types
            types_elem = probe_match.find('d:Types', ns) or probe_match.find('tns:Types', ns)
            if types_elem is not None:
                device_info['types'] = types_elem.text

            # Scopes
            scopes_elem = probe_match.find('d:Scopes', ns) or probe_match.find('tns:Scopes', ns)
            if scopes_elem is not None:
                device_info['scopes'] = scopes_elem.text

            # XAddrs
            xaddrs_elem = probe_match.find('d:XAddrs', ns) or probe_match.find('tns:XAddrs', ns)
            if xaddrs_elem is not None:
                device_info['xaddrs'] = xaddrs_elem.text

            # Metadata Version
            metadata_elem = (probe_match.find('d:MetadataVersion', ns) or
                           probe_match.find('tns:MetadataVersion', ns))
            if metadata_elem is not None:
                device_info['metadata_version'] = metadata_elem.text

        # Also check for Hello messages
        hello = root.find('.//d:Hello', ns) or root.find('.//tns:Hello', ns)
        if hello is not None:
            # Similar parsing for Hello messages
            epr = (hello.find('.//wsa:Address', ns) or
                  hello.find('wsa:EndpointReference/wsa:Address', ns))
            if epr is not None:
                device_info['endpoint_reference'] = epr.text

            types_elem = hello.find('d:Types', ns) or hello.find('tns:Types', ns)
            if types_elem is not None:
                device_info['types'] = types_elem.text

            scopes_elem = hello.find('d:Scopes', ns) or hello.find('tns:Scopes', ns)
            if scopes_elem is not None:
                device_info['scopes'] = scopes_elem.text

            xaddrs_elem = hello.find('d:XAddrs', ns) or hello.find('tns:XAddrs', ns)
            if xaddrs_elem is not None:
                device_info['xaddrs'] = xaddrs_elem.text

        return device_info

    except (ET.ParseError, UnicodeDecodeError):
        return {}


def discover_devices(target_ip: str, timeout: float = 5, verbose: bool = False) -> Dict[str, Any]:
    """Core WS-Discovery device discovery logic."""
    # Send fuzz messages and collect responses
    all_responses = fuzz_ws_discovery(target_ip, timeout=timeout, verbose=verbose)

    # Parse and deduplicate discovered devices
    discovered_devices = []
    unique_devices = set()

    for addr, response_data in all_responses:
        device_info = parse_ws_discovery_response(response_data)
        if device_info:
            device_key = (addr[0], device_info.get('endpoint_reference', 'unknown'))
            if device_key not in unique_devices:
                unique_devices.add(device_key)
                discovered_devices.append({
                    'ip': addr[0],
                    'port': addr[1],
                    **device_info
                })

    return {
        'devices_found': len(discovered_devices),
        'devices': discovered_devices,
        'total_responses': len(all_responses),
        'target_ip': target_ip
    }


class WSDiscoveryTool:
    """WS-Discovery tool implementation."""

    @property
    def name(self) -> str:
        return "wsdiscovery"

    @property
    def description(self) -> str:
        return "WS-Discovery protocol scanner for network device detection"

    def run(self, config) -> 'ToolResult':
        """Execute WS-Discovery scan."""
        from .interfaces import ToolResult
        import time

        start_time = time.time()

        try:
            timeout = config.timeout or 5.0
            verbose = config.verbose

            # Perform discovery
            result = discover_devices(config.input_path, timeout=timeout, verbose=verbose)

            execution_time = time.time() - start_time

            return ToolResult(
                success=True,
                data=result,
                errors=[],
                metadata={
                    'devices_found': result['devices_found'],
                    'total_responses': result['total_responses'],
                    'target_ip': result['target_ip']
                },
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = time.time() - start_time
            return ToolResult(
                success=False,
                data=None,
                errors=[str(e)],
                metadata={'target_ip': config.input_path},
                execution_time=execution_time
            )
