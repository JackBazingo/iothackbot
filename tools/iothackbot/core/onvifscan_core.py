"""
Core onvifscan functionality - ONVIF device scanning and testing.
Separated from CLI logic for automation and chaining.
"""

import requests
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from .interfaces import ToolInterface, ToolConfig, ToolResult


# Common SOAP envelope template
SOAP_ENVELOPE = """<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing">
    <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        {body}
    </s:Body>
</s:Envelope>"""

# ONVIF request templates (comprehensive set from Device, Media, Event, PTZ, Recording services)
REQUESTS = [
    # Device Management Service (http://www.onvif.org/ver10/device/wsdl)
    {
        "name": "GetServices",
        "endpoint": "/onvif/device_service",
        "body": '<GetServices xmlns="http://www.onvif.org/ver10/device/wsdl"><IncludeCapability>true</IncludeCapability></GetServices>',
        "auth_required": False,
        "description": "Retrieves list of supported services and their capabilities. Unauthenticated by design."
    },
    {
        "name": "GetSystemDateAndTime",
        "endpoint": "/onvif/device_service",
        "body": '<GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": False,
        "description": "Gets device date and time. Unauthenticated by design."
    },
    {
        "name": "GetCapabilities",
        "endpoint": "/onvif/device_service",
        "body": '<GetCapabilities xmlns="http://www.onvif.org/ver10/device/wsdl"><Category>All</Category></GetCapabilities>',
        "auth_required": False,
        "description": "Gets device capabilities (older version of GetServices). Unauthenticated by design."
    },
    {
        "name": "GetDeviceInformation",
        "endpoint": "/onvif/device_service",
        "body": '<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets device info (manufacturer, model, firmware). Sensitive if unauthenticated."
    },
    {
        "name": "GetHostname",
        "endpoint": "/onvif/device_service",
        "body": '<GetHostname xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets device hostname. Sensitive network info."
    },
    {
        "name": "GetNetworkInterfaces",
        "endpoint": "/onvif/device_service",
        "body": '<GetNetworkInterfaces xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets network interface details. Highly sensitive if unauthenticated."
    },
    {
        "name": "GetDNS",
        "endpoint": "/onvif/device_service",
        "body": '<GetDNS xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets DNS settings. Sensitive network config."
    },
    {
        "name": "GetNTP",
        "endpoint": "/onvif/device_service",
        "body": '<GetNTP xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets NTP server settings. Sensitive network info."
    },
    {
        "name": "GetUsers",
        "endpoint": "/onvif/device_service",
        "body": '<GetUsers xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets user account list. Critical if unauthenticated."
    },
    {
        "name": "GetNetworkProtocols",
        "endpoint": "/onvif/device_service",
        "body": '<GetNetworkProtocols xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets network protocol settings (e.g., HTTP, RTSP). Sensitive."
    },

    # Media Service (http://www.onvif.org/ver10/media/wsdl)
    {
        "name": "GetProfiles",
        "endpoint": None,  # Updated after GetServices
        "body": '<GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
        "auth_required": True,
        "description": "Gets media profiles (stream configs). Sensitive if unauthenticated."
    },
    {
        "name": "GetVideoSources",
        "endpoint": None,
        "body": '<GetVideoSources xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
        "auth_required": True,
        "description": "Gets video source details. Sensitive stream info."
    },
    {
        "name": "GetAudioSources",
        "endpoint": None,
        "body": '<GetAudioSources xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
        "auth_required": True,
        "description": "Gets audio source information. Sensitive audio surveillance."
    },
    {
        "name": "GetSnapshotUri",
        "endpoint": None,
        "body": '<GetSnapshotUri xmlns="http://www.onvif.org/ver10/media/wsdl"><ProfileToken>Profile_1</ProfileToken></GetSnapshotUri>',
        "auth_required": True,
        "description": "Gets snapshot URI. Critical if unauthenticated (image access)."
    },
    {
        "name": "GetStreamUri",
        "endpoint": None,
        "body": '<GetStreamUri xmlns="http://www.onvif.org/ver10/media/wsdl"><StreamSetup><Stream xmlns="http://www.onvif.org/ver10/schema">RTP-Unicast</Stream><Transport xmlns="http://www.onvif.org/ver10/schema"><Protocol>RTSP</Protocol></Transport></StreamSetup><ProfileToken>Profile_1</ProfileToken></GetStreamUri>',
        "auth_required": True,
        "description": "Gets RTSP stream URI. Critical if unauthenticated (video access)."
    },

    # Event Service (http://www.onvif.org/ver10/events/wsdl)
    {
        "name": "GetEventProperties",
        "endpoint": None,
        "body": '<GetEventProperties xmlns="http://www.onvif.org/ver10/events/wsdl"/>',
        "auth_required": False,
        "description": "Gets event properties (e.g., supported events). Unauthenticated by design."
    },

    # PTZ Service (http://www.onvif.org/ver20/ptz/wsdl)
    {
        "name": "GetNodes",
        "endpoint": None,
        "body": '<GetNodes xmlns="http://www.onvif.org/ver20/ptz/wsdl"/>',
        "auth_required": True,
        "description": "Gets PTZ nodes. Sensitive if unauthenticated (camera control)."
    },
    {
        "name": "GetPresets",
        "endpoint": None,
        "body": '<GetPresets xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>Profile_1</ProfileToken></GetPresets>',
        "auth_required": True,
        "description": "Gets PTZ presets. Sensitive if unauthenticated."
    },

    # Imaging Service (http://www.onvif.org/ver20/imaging/wsdl)
    {
        "name": "GetImagingSettings",
        "endpoint": None,
        "body": '<GetImagingSettings xmlns="http://www.onvif.org/ver20/imaging/wsdl"><VideoSourceToken>VideoSource_1</VideoSourceToken></GetImagingSettings>',
        "auth_required": True,
        "description": "Gets camera imaging settings (brightness, contrast, etc.). Sensitive camera config."
    },

    # Recording Service (http://www.onvif.org/ver10/recording/wsdl)
    {
        "name": "GetRecordings",
        "endpoint": None,
        "body": '<GetRecordings xmlns="http://www.onvif.org/ver10/recording/wsdl"/>',
        "auth_required": True,
        "description": "Gets list of recordings. Critical if unauthenticated (video access)."
    },

    # Device IO Service (http://www.onvif.org/ver10/deviceIO/wsdl)
    {
        "name": "GetDigitalInputs",
        "endpoint": "/onvif/deviceio",
        "body": '<GetDigitalInputs xmlns="http://www.onvif.org/ver10/deviceIO/wsdl"/>',
        "auth_required": True,
        "description": "Gets digital input status/configuration. Sensitive I/O info."
    },
    {
        "name": "GetRelayOutputs",
        "endpoint": "/onvif/deviceio",
        "body": '<GetRelayOutputs xmlns="http://www.onvif.org/ver10/deviceIO/wsdl"/>',
        "auth_required": True,
        "description": "Gets relay output status/configuration. Critical for physical access control."
    },

    # Search Service (http://www.onvif.org/ver10/search/wsdl)
    {
        "name": "GetSearchCapabilities",
        "endpoint": "/onvif/search",
        "body": '<GetServiceCapabilities xmlns="http://www.onvif.org/ver10/search/wsdl"/>',
        "auth_required": False,
        "description": "Gets search service capabilities. Unauthenticated by design."
    },

    # Additional Device Management operations
    {
        "name": "GetDynamicDNS",
        "endpoint": "/onvif/device_service",
        "body": '<GetDynamicDNS xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets dynamic DNS settings. Sensitive network configuration."
    },
    {
        "name": "GetZeroConfiguration",
        "endpoint": "/onvif/device_service",
        "body": '<GetZeroConfiguration xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets zeroconf/UPnP settings. Could leak network topology."
    },
    {
        "name": "GetScopes",
        "endpoint": "/onvif/device_service",
        "body": '<GetScopes xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": False,
        "description": "Gets device scopes (location, hardware info). Unauthenticated by design."
    },
    {
        "name": "GetCertificatesStatus",
        "endpoint": "/onvif/device_service",
        "body": '<GetCertificatesStatus xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets certificate status. Privacy risk if unauthenticated."
    },
    {
        "name": "GetDiscoveryMode",
        "endpoint": "/onvif/device_service",
        "body": '<GetDiscoveryMode xmlns="http://www.onvif.org/ver10/device/wsdl"/>',
        "auth_required": True,
        "description": "Gets discovery mode settings. Reveals network discoverability."
    },

    # Additional Media Service operations
    {
        "name": "GetVideoEncoderConfigurations",
        "endpoint": None,
        "body": '<GetVideoEncoderConfigurations xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
        "auth_required": True,
        "description": "Gets video encoder configurations. Sensitive stream details."
    },
    {
        "name": "GetMetadataConfigurations",
        "endpoint": None,
        "body": '<GetMetadataConfigurations xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
        "auth_required": True,
        "description": "Gets metadata configurations. Could leak analytics data."
    },
    {
        "name": "GetCompatibleVideoSources",
        "endpoint": None,
        "body": '<GetCompatibleVideoSources xmlns="http://www.onvif.org/ver10/media/wsdl"><ProfileToken>Profile_1</ProfileToken></GetCompatibleVideoSources>',
        "auth_required": True,
        "description": "Gets compatible video sources for a profile. Sensitive video info."
    },
    {
        "name": "GetServiceCapabilities",
        "endpoint": None,
        "body": '<GetServiceCapabilities xmlns="http://www.onvif.org/ver10/media/wsdl"/>',
        "auth_required": False,
        "description": "Gets media service capabilities. Unauthenticated by design."
    },

    # Additional Events Service operations
    {
        "name": "CreatePullPointSubscription",
        "endpoint": None,
        "body": '<CreatePullPointSubscription xmlns="http://www.onvif.org/ver10/events/wsdl"><InitialTerminationTime>PT60S</InitialTerminationTime></CreatePullPointSubscription>',
        "auth_required": True,
        "description": "Creates event subscription. DoS/info leak risk if unauthenticated."
    },
    {
        "name": "GetEventBrokers",
        "endpoint": None,
        "body": '<GetEventBrokers xmlns="http://www.onvif.org/ver10/events/wsdl"/>',
        "auth_required": True,
        "description": "Gets event brokers. Sensitive event infrastructure info."
    },

    # Additional PTZ Service operations
    {
        "name": "GetConfigurations",
        "endpoint": None,
        "body": '<GetConfigurations xmlns="http://www.onvif.org/ver20/ptz/wsdl"/>',
        "auth_required": True,
        "description": "Gets PTZ configurations. Sensitive camera movement limits."
    },
    {
        "name": "GetStatus",
        "endpoint": None,
        "body": '<GetStatus xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>Profile_1</ProfileToken></GetStatus>',
        "auth_required": True,
        "description": "Gets current PTZ status. Privacy violation if unauthenticated."
    },

    # Additional Imaging Service operations
    {
        "name": "GetOptions",
        "endpoint": None,
        "body": '<GetOptions xmlns="http://www.onvif.org/ver20/imaging/wsdl"><VideoSourceToken>VideoSource_1</VideoSourceToken></GetOptions>',
        "auth_required": True,
        "description": "Gets imaging options. Sensitive camera capabilities."
    },

    # Additional Recording Service operations
    {
        "name": "GetRecordingConfiguration",
        "endpoint": None,
        "body": '<GetRecordingConfiguration xmlns="http://www.onvif.org/ver10/recording/wsdl"><RecordingToken>Recording_1</RecordingToken></GetRecordingConfiguration>',
        "auth_required": True,
        "description": "Gets recording configuration. Critical recording details."
    },
    {
        "name": "ExportRecordedData",
        "endpoint": None,
        "body": '<ExportRecordedData xmlns="http://www.onvif.org/ver10/recording/wsdl"><SearchScope><IncludedSources><Token>Recording_1</Token></IncludedSources></SearchScope><FileFormat>MP4</FileFormat></ExportRecordedData>',
        "auth_required": True,
        "description": "Exports recorded data. Huge privacy risk if unauthenticated."
    },

    # Additional Replay Service operations
    {
        "name": "GetReplayUri",
        "endpoint": "/onvif/replay",
        "body": '<GetReplayUri xmlns="http://www.onvif.org/ver10/replay/wsdl"><StreamSetup><Stream xmlns="http://www.onvif.org/ver10/schema">RTP-Unicast</Stream><Transport xmlns="http://www.onvif.org/ver10/schema"><Protocol>RTSP</Protocol></Transport></StreamSetup><RecordingToken>Recording_1</RecordingToken></GetReplayUri>',
        "auth_required": True,
        "description": "Gets replay URI. Critical for accessing recordings."
    },

    # Analytics Service operations
    {
        "name": "GetSupportedAnalyticsModules",
        "endpoint": None,
        "body": '<GetSupportedAnalyticsModules xmlns="http://www.onvif.org/ver20/analytics/wsdl"><ConfigurationToken>Analytics_1</ConfigurationToken></GetSupportedAnalyticsModules>',
        "auth_required": True,
        "description": "Gets supported analytics modules. Sensitive video analytics."
    },
    {
        "name": "GetAnalyticsDeviceInformation",
        "endpoint": None,
        "body": '<GetAnalyticsDeviceInformation xmlns="http://www.onvif.org/ver20/analytics/wsdl"/>',
        "auth_required": True,
        "description": "Gets analytics device information. Reveals analytics engine details."
    },

    # Additional Device IO Service operations
    {
        "name": "GetSerialPorts",
        "endpoint": "/onvif/deviceio",
        "body": '<GetSerialPorts xmlns="http://www.onvif.org/ver10/deviceIO/wsdl"/>',
        "auth_required": True,
        "description": "Gets serial port configurations. Hardware interface details."
    },
    {
        "name": "SetRelayOutputState",
        "endpoint": "/onvif/deviceio",
        "body": '<SetRelayOutputState xmlns="http://www.onvif.org/ver10/deviceIO/wsdl"><RelayOutputToken>Relay_1</RelayOutputToken><LogicalState>false</LogicalState></SetRelayOutputState>',
        "auth_required": True,
        "description": "Sets relay output state. Critical for physical control if unauthenticated."
    },

    # Additional Search Service operations
    {
        "name": "FindEvents",
        "endpoint": "/onvif/search",
        "body": '<FindEvents xmlns="http://www.onvif.org/ver10/search/wsdl"><StartPoint>2023-01-01T00:00:00Z</StartPoint><EndPoint>2023-01-02T00:00:00Z</EndPoint></FindEvents>',
        "auth_required": True,
        "description": "Searches for events. Could leak historical event data."
    },

    # Receiver Service operations
    {
        "name": "GetReceivers",
        "endpoint": "/onvif/receiver",
        "body": '<GetReceivers xmlns="http://www.onvif.org/ver10/receiver/wsdl"/>',
        "auth_required": True,
        "description": "Gets receiver configurations. Sensitive stream receiver details."
    },

    # Provisioning Service operations
    {
        "name": "GetProvisioning",
        "endpoint": "/onvif/provisioning",
        "body": '<GetProvisioning xmlns="http://www.onvif.org/ver10/provisioning/wsdl"/>',
        "auth_required": True,
        "description": "Gets provisioning information. Device setup details."
    },

    # Advanced Security Service operations
    {
        "name": "GetSupportedKeystores",
        "endpoint": "/onvif/advancedsecurity",
        "body": '<GetSupportedKeystores xmlns="http://www.onvif.org/ver10/advancedsecurity/wsdl"/>',
        "auth_required": True,
        "description": "Gets supported keystores. Certificate management info."
    },

    # DESTRUCTIVE/NICHE OPERATIONS - Only run with -a/--all flag
    # PTZ Service - Destructive
    {
        "name": "ContinuousMove",
        "endpoint": None,
        "body": '<ContinuousMove xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>Profile_1</ProfileToken><Velocity><PanTilt x="0.0" y="0.0" xmlns="http://www.onvif.org/ver10/schema"/></Velocity></ContinuousMove>',
        "auth_required": True,
        "description": "Attempts continuous PTZ movement (destructive - may move camera).",
        "destructive": True
    },
    {
        "name": "AbsoluteMove",
        "endpoint": None,
        "body": '<AbsoluteMove xmlns="http://www.onvif.org/ver20/ptz/wsdl"><ProfileToken>Profile_1</ProfileToken><Position><PanTilt x="0.0" y="0.0" xmlns="http://www.onvif.org/ver10/schema"/><Zoom x="1.0" xmlns="http://www.onvif.org/ver10/schema"/></Position></AbsoluteMove>',
        "auth_required": True,
        "description": "Attempts absolute PTZ movement (destructive - may move camera).",
        "destructive": True
    },

    # Imaging Service - Destructive
    {
        "name": "Move",
        "endpoint": None,
        "body": '<Move xmlns="http://www.onvif.org/ver20/imaging/wsdl"><VideoSourceToken>VideoSource_1</VideoSourceToken><Focus><Absolute>50</Absolute></Focus></Move>',
        "auth_required": True,
        "description": "Attempts to move camera focus (destructive - may adjust lens).",
        "destructive": True
    },
    {
        "name": "Stop",
        "endpoint": None,
        "body": '<Stop xmlns="http://www.onvif.org/ver20/imaging/wsdl"><VideoSourceToken>VideoSource_1</VideoSourceToken></Stop>',
        "auth_required": True,
        "description": "Attempts to stop imaging movement (destructive).",
        "destructive": True
    },

    # Recording Service - Destructive
    {
        "name": "CreateRecording",
        "endpoint": None,
        "body": '<CreateRecording xmlns="http://www.onvif.org/ver10/recording/wsdl"><RecordingConfiguration><Source><SourceToken>VideoSource_1</SourceToken><Name>TestRecording</Name></Source><Content>Video</Content></RecordingConfiguration></CreateRecording>',
        "auth_required": True,
        "description": "Attempts to create a recording (destructive - may create storage).",
        "destructive": True
    },
    {
        "name": "DeleteRecording",
        "endpoint": None,
        "body": '<DeleteRecording xmlns="http://www.onvif.org/ver10/recording/wsdl"><RecordingToken>Recording_1</RecordingToken></DeleteRecording>',
        "auth_required": True,
        "description": "Attempts to delete a recording (destructive - may delete data).",
        "destructive": True
    },

    # Analytics Service - Destructive
    {
        "name": "CreateAnalyticsModules",
        "endpoint": None,
        "body": '<CreateAnalyticsModules xmlns="http://www.onvif.org/ver20/analytics/wsdl"><ConfigurationToken>Analytics_1</ConfigurationToken><AnalyticsModule><Name>TestModule</Name><Type>tt:CellMotionDetector</Type></AnalyticsModule></CreateAnalyticsModules>',
        "auth_required": True,
        "description": "Attempts to create analytics modules (destructive - may add processing rules).",
        "destructive": True
    },

    # Device Management Service - Highly Destructive
    {
        "name": "SetSystemFactoryDefault",
        "endpoint": "/onvif/device_service",
        "body": '<SetSystemFactoryDefault xmlns="http://www.onvif.org/ver10/device/wsdl"><FactoryDefault>Hard</FactoryDefault></SetSystemFactoryDefault>',
        "auth_required": True,
        "description": "Attempts to reset system to factory defaults (highly destructive).",
        "destructive": True
    },
    {
        "name": "UpgradeSystemFirmware",
        "endpoint": "/onvif/device_service",
        "body": '<UpgradeSystemFirmware xmlns="http://www.onvif.org/ver10/device/wsdl"><Firmware><Data>test</Data></Firmware></UpgradeSystemFirmware>',
        "auth_required": True,
        "description": "Attempts firmware upgrade (highly destructive).",
        "destructive": True
    },

    # Receiver Service - Destructive
    {
        "name": "CreateReceiver",
        "endpoint": "/onvif/receiver",
        "body": '<CreateReceiver xmlns="http://www.onvif.org/ver10/receiver/wsdl"><Configuration><Mode>AutoConnect</Mode><MediaUri>http://example.com/stream</MediaUri></Configuration></CreateReceiver>',
        "auth_required": True,
        "description": "Attempts to create a receiver (destructive - may add stream receiver).",
        "destructive": True
    },

    # Events Service - Potentially Destructive (if subscriptions exist)
    {
        "name": "Renew",
        "endpoint": None,
        "body": '<Renew xmlns="http://www.onvif.org/ver10/events/wsdl"><TerminationTime>PT60S</TerminationTime></Renew>',
        "auth_required": True,
        "description": "Attempts to renew event subscription (potentially destructive).",
        "destructive": True
    },
    {
        "name": "Unsubscribe",
        "endpoint": None,
        "body": '<Unsubscribe xmlns="http://www.onvif.org/ver10/events/wsdl"/>',
        "auth_required": True,
        "description": "Attempts to unsubscribe from events (potentially destructive).",
        "destructive": True
    },

    # Niche Services - Uncovered but potentially testable
    # Access Control Service
    {
        "name": "GetAccessPointInfo",
        "endpoint": "/onvif/accesscontrol",
        "body": '<GetAccessPointInfo xmlns="http://www.onvif.org/ver10/accesscontrol/wsdl"><Token>AccessPoint_1</Token></GetAccessPointInfo>',
        "auth_required": True,
        "description": "Gets access point information (physical security info).",
        "destructive": False  # Not destructive, but niche
    },

    # Door Control Service
    {
        "name": "GetDoorState",
        "endpoint": "/onvif/doorcontrol",
        "body": '<GetDoorState xmlns="http://www.onvif.org/ver10/doorcontrol/wsdl"><Token>Door_1</Token></GetDoorState>',
        "auth_required": True,
        "description": "Gets door state (physical access status).",
        "destructive": False  # Not destructive, but niche
    },

    # Credential Service
    {
        "name": "GetCredentials",
        "endpoint": "/onvif/credential",
        "body": '<GetCredentials xmlns="http://www.onvif.org/ver10/credential/wsdl"/>',
        "auth_required": True,
        "description": "Gets credential information (critical security data).",
        "destructive": False  # Not destructive, but niche
    }
]

# Headers for SOAP requests
HEADERS = {
    "Content-Type": "application/soap+xml; charset=utf-8"
}

# Stub functions for new subcommands (to be expanded later)
def brute(config: ToolConfig) -> ToolResult:
    """Full implementation would go here for credential brute-forcing."""
    # Use config.input_path for URL, config.custom_args['wordlist'] for creds list
    # Run auth scan first, then brute on 401 endpoints
    auth_result = OnvifScanTool().run(config)  # Chain with auth
    # Brute logic...
    return ToolResult(success=True, data={"brute_results": "Stub: Found vulnerable creds"})

def check_vulns(config: ToolConfig) -> ToolResult:
    """Full implementation would go here for vulnerability checking."""
    # Parse firmware from auth scan
    auth_result = OnvifScanTool().run(config)
    # CVE matching logic...
    return ToolResult(success=True, data={"vuln_results": "Stub: 2 CVEs found"})


def send_request(request: Dict[str, Any], url: str, timeout: float = 5.0) -> Dict[str, Any]:
    """Send SOAP request and return response details."""
    soap_body = SOAP_ENVELOPE.format(body=request["body"])
    try:
        response = requests.post(url, headers=HEADERS, data=soap_body, timeout=timeout)
        return {
            "status_code": response.status_code,
            "content": response.text,
            "success": response.status_code == 200 and "Fault" not in response.text
        }
    except requests.RequestException as e:
        return {
            "status_code": None,
            "content": str(e),
            "success": False
        }


def parse_get_services(response_text: str) -> Dict[str, str]:
    """Parse GetServices response to extract service endpoints."""
    endpoints = {}
    try:
        root = ET.fromstring(response_text)
        ns = {"ns": "http://www.onvif.org/ver10/device/wsdl"}
        services = root.findall(".//ns:Service", namespaces=ns)
        for service in services:
            namespace = service.find("ns:Namespace", namespaces=ns)
            xaddr = service.find("ns:XAddr", namespaces=ns)
            if namespace is not None and xaddr is not None:
                endpoints[namespace.text] = xaddr.text
    except ET.ParseError:
        pass  # Silently fail parsing
    return endpoints


def scan_onvif_device(base_url: str, test_all: bool = False, timeout: float = 5.0, verbose: bool = False) -> Dict[str, Any]:
    """Core ONVIF scanning logic."""
    base_url = base_url.rstrip('/')

    # First, get service endpoints
    get_services = next(req for req in REQUESTS if req["name"] == "GetServices")
    url = f"{base_url}{get_services['endpoint']}"
    response = send_request(get_services, url, timeout)

    if not response["success"]:
        return {
            'services_discovered': False,
            'error': 'Failed to retrieve services',
            'results': []
        }

    # Parse service endpoints
    endpoints = parse_get_services(response["content"])

    # Update request endpoints based on discovered services
    updated_requests = []
    for req in REQUESTS:
        req_copy = req.copy()

        # Skip destructive operations unless comprehensive mode (-a/--all)
        if req.get("destructive", False) and not test_all:
            continue

        if req["endpoint"] is None:
            # Look up service endpoint
            namespace = {
                # Media Service
                "GetProfiles": "http://www.onvif.org/ver10/media/wsdl",
                "GetVideoSources": "http://www.onvif.org/ver10/media/wsdl",
                "GetAudioSources": "http://www.onvif.org/ver10/media/wsdl",
                "GetSnapshotUri": "http://www.onvif.org/ver10/media/wsdl",
                "GetStreamUri": "http://www.onvif.org/ver10/media/wsdl",
                "GetVideoEncoderConfigurations": "http://www.onvif.org/ver10/media/wsdl",
                "GetMetadataConfigurations": "http://www.onvif.org/ver10/media/wsdl",
                "GetCompatibleVideoSources": "http://www.onvif.org/ver10/media/wsdl",
                "GetServiceCapabilities": "http://www.onvif.org/ver10/media/wsdl",
                # Events Service
                "GetEventProperties": "http://www.onvif.org/ver10/events/wsdl",
                "CreatePullPointSubscription": "http://www.onvif.org/ver10/events/wsdl",
                "GetEventBrokers": "http://www.onvif.org/ver10/events/wsdl",
                # PTZ Service
                "GetNodes": "http://www.onvif.org/ver20/ptz/wsdl",
                "GetPresets": "http://www.onvif.org/ver20/ptz/wsdl",
                "GetConfigurations": "http://www.onvif.org/ver20/ptz/wsdl",
                "GetStatus": "http://www.onvif.org/ver20/ptz/wsdl",
                # Imaging Service
                "GetImagingSettings": "http://www.onvif.org/ver20/imaging/wsdl",
                "GetOptions": "http://www.onvif.org/ver20/imaging/wsdl",
                # Recording Service
                "GetRecordings": "http://www.onvif.org/ver10/recording/wsdl",
                "GetRecordingConfiguration": "http://www.onvif.org/ver10/recording/wsdl",
                "ExportRecordedData": "http://www.onvif.org/ver10/recording/wsdl",
                # Analytics Service
                "GetSupportedAnalyticsModules": "http://www.onvif.org/ver20/analytics/wsdl",
                "GetAnalyticsDeviceInformation": "http://www.onvif.org/ver20/analytics/wsdl",
                # Destructive Operations
                "ContinuousMove": "http://www.onvif.org/ver20/ptz/wsdl",
                "AbsoluteMove": "http://www.onvif.org/ver20/ptz/wsdl",
                "Move": "http://www.onvif.org/ver20/imaging/wsdl",
                "Stop": "http://www.onvif.org/ver20/imaging/wsdl",
                "CreateRecording": "http://www.onvif.org/ver10/recording/wsdl",
                "DeleteRecording": "http://www.onvif.org/ver10/recording/wsdl",
                "CreateAnalyticsModules": "http://www.onvif.org/ver20/analytics/wsdl",
                "Renew": "http://www.onvif.org/ver10/events/wsdl",
                "Unsubscribe": "http://www.onvif.org/ver10/events/wsdl",
            }.get(req["name"])

            if namespace and namespace in endpoints:
                req_copy["endpoint"] = endpoints[namespace]
                updated_requests.append(req_copy)
                # In comprehensive mode, also try fallback endpoints
                if test_all:
                    fallback_endpoints = {
                        # Media Service
                        "GetProfiles": "/onvif/media",
                        "GetVideoSources": "/onvif/media",
                        "GetAudioSources": "/onvif/media",
                        "GetSnapshotUri": "/onvif/media",
                        "GetStreamUri": "/onvif/media",
                        "GetVideoEncoderConfigurations": "/onvif/media",
                        "GetMetadataConfigurations": "/onvif/media",
                        "GetCompatibleVideoSources": "/onvif/media",
                        "GetServiceCapabilities": "/onvif/media",
                        # Events Service
                        "GetEventProperties": "/onvif/events",
                        "CreatePullPointSubscription": "/onvif/events",
                        "GetEventBrokers": "/onvif/events",
                        # PTZ Service
                        "GetNodes": "/onvif/ptz",
                        "GetPresets": "/onvif/ptz",
                        "GetConfigurations": "/onvif/ptz",
                        "GetStatus": "/onvif/ptz",
                        # Imaging Service
                        "GetImagingSettings": "/onvif/imaging",
                        "GetOptions": "/onvif/imaging",
                        # Recording Service
                        "GetRecordings": "/onvif/recording",
                        "GetRecordingConfiguration": "/onvif/recording",
                        "ExportRecordedData": "/onvif/recording",
                    # Analytics Service
                    "GetSupportedAnalyticsModules": "/onvif/analytics",
                    "GetAnalyticsDeviceInformation": "/onvif/analytics",
                    # Destructive Operations
                    "ContinuousMove": "/onvif/ptz",
                    "AbsoluteMove": "/onvif/ptz",
                    "Move": "/onvif/imaging",
                    "Stop": "/onvif/imaging",
                    "CreateRecording": "/onvif/recording",
                    "DeleteRecording": "/onvif/recording",
                    "CreateAnalyticsModules": "/onvif/analytics",
                    "Renew": "/onvif/events",
                    "Unsubscribe": "/onvif/events",
                }
                    fallback = fallback_endpoints.get(req["name"])
                    if fallback:
                        req_fallback = req.copy()
                        req_fallback["endpoint"] = base_url + fallback
                        req_fallback["name"] = f"{req['name']} (fallback)"
                        updated_requests.append(req_fallback)
            elif test_all:
                # In comprehensive mode, try fallback endpoints
                fallback_endpoints = {
                    # Media Service
                    "GetProfiles": "/onvif/media",
                    "GetVideoSources": "/onvif/media",
                    "GetAudioSources": "/onvif/media",
                    "GetSnapshotUri": "/onvif/media",
                    "GetStreamUri": "/onvif/media",
                    "GetVideoEncoderConfigurations": "/onvif/media",
                    "GetMetadataConfigurations": "/onvif/media",
                    "GetCompatibleVideoSources": "/onvif/media",
                    "GetServiceCapabilities": "/onvif/media",
                    # Events Service
                    "GetEventProperties": "/onvif/events",
                    "CreatePullPointSubscription": "/onvif/events",
                    "GetEventBrokers": "/onvif/events",
                    # PTZ Service
                    "GetNodes": "/onvif/ptz",
                    "GetPresets": "/onvif/ptz",
                    "GetConfigurations": "/onvif/ptz",
                    "GetStatus": "/onvif/ptz",
                    # Imaging Service
                    "GetImagingSettings": "/onvif/imaging",
                    "GetOptions": "/onvif/imaging",
                    # Recording Service
                    "GetRecordings": "/onvif/recording",
                    "GetRecordingConfiguration": "/onvif/recording",
                    "ExportRecordedData": "/onvif/recording",
                    # Analytics Service
                    "GetSupportedAnalyticsModules": "/onvif/analytics",
                    "GetAnalyticsDeviceInformation": "/onvif/analytics",
                    # Destructive Operations
                    "ContinuousMove": "/onvif/ptz",
                    "AbsoluteMove": "/onvif/ptz",
                    "Move": "/onvif/imaging",
                    "Stop": "/onvif/imaging",
                    "CreateRecording": "/onvif/recording",
                    "DeleteRecording": "/onvif/recording",
                    "CreateAnalyticsModules": "/onvif/analytics",
                    "Renew": "/onvif/events",
                    "Unsubscribe": "/onvif/events",
                }
                fallback = fallback_endpoints.get(req["name"])
                if fallback:
                    req_copy["endpoint"] = base_url + fallback
                    updated_requests.append(req_copy)
                else:
                    req_copy["endpoint"] = False
                    updated_requests.append(req_copy)
            else:
                req_copy["endpoint"] = False
                updated_requests.append(req_copy)
        elif isinstance(req["endpoint"], str) and req["endpoint"].startswith('/'):
            req_copy["endpoint"] = base_url + req["endpoint"]
            updated_requests.append(req_copy)

    # Test each request
    results = []
    for req in updated_requests:
        if req["endpoint"] is False:
            results.append({
                "name": req["name"],
                "status_code": "SKIPPED",
                "result": "Service endpoint not found",
                "auth_required": req["auth_required"],
                "endpoint": None
            })
            continue

        url = req["endpoint"]
        response = send_request(req, url, timeout)

        # Determine result message
        if response["success"] and req["auth_required"]:
            result_msg = "SECURITY ISSUE: responded without authentication!"
            security_issue = True
        elif response["success"]:
            result_msg = "responded as expected (unauthenticated by design)"
            security_issue = False
        elif response["status_code"] == 401 or "NotAuthorized" in response["content"]:
            result_msg = "requires authentication (secure)"
            security_issue = False
        else:
            result_msg = f"failed: {response['content'][:50]}..."
            security_issue = False

        results.append({
            "name": req["name"],
            "status_code": response["status_code"] or "ERROR",
            "result": result_msg,
            "auth_required": req["auth_required"],
            "endpoint": url,
            "security_issue": security_issue,
            "response_content": response["content"] if verbose or len(response["content"]) < 1000 else response["content"][:1000] + "..."
        })

    # Group results by status code for summary
    from collections import defaultdict
    grouped_results = defaultdict(list)
    security_issues = []

    for result in results:
        grouped_results[result["status_code"]].append(result)
        if result.get("security_issue", False):
            security_issues.append(result)

    return {
        'services_discovered': True,
        'endpoints_discovered': endpoints,
        'total_tests': len(results),
        'security_issues': security_issues,
        'results_by_status': dict(grouped_results),
        'all_results': results
    }


class OnvifScanTool(ToolInterface):
    """OnvifScan tool implementation."""

    @property
    def name(self) -> str:
        return "onvifscan"

    @property
    def description(self) -> str:
        return "ONVIF unauthenticated access scanner for network devices"

    def run(self, config: ToolConfig) -> ToolResult:
        """Execute onvifscan analysis."""
        import time
        start_time = time.time()

        try:
            test_all = config.custom_args.get('all', False)
            timeout = config.timeout or 5.0
            verbose = config.verbose

            # Perform scanning
            scan_result = scan_onvif_device(config.input_path, test_all, timeout, verbose)

            execution_time = time.time() - start_time

            return ToolResult(
                success=scan_result.get('services_discovered', False),
                data=scan_result,
                errors=[scan_result.get('error')] if 'error' in scan_result else [],
                metadata={
                    'total_tests': scan_result.get('total_tests', 0),
                    'security_issues_count': len(scan_result.get('security_issues', [])),
                    'endpoints_discovered': len(scan_result.get('endpoints_discovered', {})),
                    'target_url': config.input_path,
                    'test_all': test_all
                },
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = time.time() - start_time
            return ToolResult(
                success=False,
                data=None,
                errors=[str(e)],
                metadata={'target_url': config.input_path},
                execution_time=execution_time
            )
