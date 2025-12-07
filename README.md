# IoTHackBot

Open-source IoT security testing toolkit with integrated Claude Code skills for automated vulnerability discovery.

## Overview

IoTHackBot is a collection of specialized tools and Claude Code skills designed for security testing of IoT devices, IP cameras, and embedded systems. It provides both command-line tools and AI-assisted workflows for comprehensive IoT security assessments.

## Tools Included

### Network Discovery & Reconnaissance

- **wsdiscovery** - WS-Discovery protocol scanner for discovering ONVIF cameras and IoT devices
- **iotnet** - IoT network traffic analyzer for detecting protocols and vulnerabilities
- **nmap-scan** (skill) - Professional network reconnaissance with two-phase scanning strategy

### Device-Specific Testing

- **onvifscan** - ONVIF device security scanner
  - Authentication bypass testing
  - Credential brute-forcing

### Firmware & File Analysis

- **ffind** - Advanced file finder with type detection and filesystem extraction
  - Identifies artifact file types
  - Extracts ext2/3/4 and F2FS filesystems
  - Designed for firmware analysis

- **ghidra** - Automated binary analysis using Ghidra/PyGhidra
  - Decompilation to pseudo-C code
  - Dangerous function detection (strcpy, system, sprintf, etc.)
  - String extraction with pattern matching
  - Cross-reference analysis
  - Supports ARM, MIPS, x86 architectures

### Android/Mobile Analysis

- **apktool** (skill) - Android APK unpacking and resource extraction
  - Decode APK resources to readable formats
  - Extract AndroidManifest.xml
  - Analyze smali bytecode
  - Repackage modified APKs

- **jadx** (skill) - Android APK decompilation
  - Convert DEX bytecode to readable Java source
  - Deobfuscation support
  - Find hardcoded credentials and API keys
  - Analyze app logic and control flow

### Hardware & Console Access

- **picocom** (skill) - IoT UART console interaction for hardware testing
  - Bootloader manipulation
  - Shell enumeration
  - Firmware extraction
  - Includes Python helper script for automated interaction

- **telnetshell** (skill) - IoT telnet shell interaction
  - Unauthenticated shell testing
  - Device enumeration
  - BusyBox command handling
  - Includes Python helper script and pre-built enumeration scripts

## Installation

### Prerequisites

```bash
# Python dependencies
pip install colorama pyserial pexpect requests

# For binary analysis (ghidra skill)
pip install pyghidra
# Also requires Ghidra 11.0+ installed and GHIDRA_INSTALL_DIR set

# System dependencies (Arch Linux)
sudo pacman -S nmap e2fsprogs f2fs-tools python python-pip inetutils

# For Android analysis (optional)
sudo pacman -S jadx apktool  # Or install via AUR/manually

# For other distributions, install equivalent packages
```

### Setup

1. Clone the repository:
```bash
git clone https://github.com/BrownFineSecurity/iothackbot.git
cd iothackbot
```

2. Add the bin directory to your PATH:
```bash
export PATH="$PATH:$(pwd)/bin"
```

3. For permanent setup, add to your shell configuration:
```bash
echo 'export PATH="$PATH:/path/to/iothackbot/bin"' >> ~/.bashrc
```

## Usage

### Quick Start Examples

#### Discover ONVIF Devices
```bash
wsdiscovery 192.168.1.0/24
```

#### Test ONVIF Device Security
```bash
onvifscan auth http://192.168.1.100
onvifscan brute http://192.168.1.100
```

#### Analyze Network Traffic
```bash
# Analyze PCAP file
iotnet capture.pcap

# Live capture
sudo iotnet -i eth0 -d 60
```

#### Analyze Firmware
```bash
# Identify file types
ffind firmware.bin

# Extract filesystems (requires sudo)
sudo ffind firmware.bin -e
```

#### Analyze Binaries
```bash
# Quick security triage
ghidra /path/to/binary --action quick

# Find dangerous function calls
ghidra /path/to/binary --action dangerous

# Decompile specific function
ghidra /path/to/binary --action decompile --function main
```

#### Analyze Android APKs
```bash
# Decompile APK to Java source (via jadx skill)
jadx --deobf app.apk -d app-decompiled

# Extract APK resources (via apktool skill)
apktool d app.apk -o app-unpacked
```

### Claude Code Skills

IoTHackBot includes specialized skills for Claude Code that provide guided, interactive security testing:

- **apktool** - Android APK unpacking and resource extraction
- **ffind** - Firmware file analysis with extraction
- **ghidra** - Automated binary analysis and decompilation
- **iotnet** - Network traffic analysis
- **jadx** - Android APK decompilation to Java source
- **nmap-scan** - Professional network reconnaissance
- **onvifscan** - ONVIF device security testing
- **picocom** - UART console interaction
- **telnetshell** - Telnet shell enumeration
- **wsdiscovery** - WS-Discovery device discovery

To use these skills with Claude Code, they are automatically available in the `.claude/skills/` directory.

## Tool Architecture

All tools follow a consistent design pattern:

- **CLI Layer** (`tools/iothackbot/*.py`) - Command-line interface with argparse
- **Core Layer** (`tools/iothackbot/core/*_core.py`) - Core functionality implementing ToolInterface
- **Binary** (`bin/*`) - Executable wrapper scripts

This separation enables:
- Easy automation and chaining
- Consistent output formats (text, JSON, quiet)
- Standardized error handling
- Tool composition and pipelines

## Configuration

### IoT Detection Rules
`config/iot/detection_rules.json` - Custom IoT protocol detection rules for iotnet

### Wordlists
- `wordlists/onvif-usernames.txt` - Default usernames for ONVIF devices
- `wordlists/onvif-passwords.txt` - Default passwords for ONVIF devices

## Development

### Adding New Tools

See `TOOL_DEVELOPMENT_GUIDE.md` for detailed information on:
- Project structure standards
- Development patterns
- Output formatting guidelines
- Testing and integration

### Key Interfaces

- **ToolInterface** - Base interface for all tools
- **ToolConfig** - Standardized configuration object
- **ToolResult** - Standardized result object with success, data, errors, and metadata

## Output Formats

All tools support multiple output formats:

```bash
# Human-readable text with colors (default)
onvifscan auth 192.168.1.100

# Machine-readable JSON
onvifscan auth 192.168.1.100 --format json

# Minimal output
onvifscan auth 192.168.1.100 --format quiet
```

## Security & Ethics

**IMPORTANT**: These tools are designed for authorized security testing only.

- Only test devices you own or have explicit permission to test
- Respect scope limitations and rules of engagement
- Be aware of the impact on production systems
- Use appropriate timing to avoid denial of service
- Document all testing activities
- Follow responsible disclosure practices

## Contributing

Contributions are welcome! Please ensure:

- New tools follow the architecture patterns in `TOOL_DEVELOPMENT_GUIDE.md`
- All tools support text, JSON, and quiet output formats
- Code includes proper error handling
- Documentation is clear and comprehensive

## License

MIT License - See LICENSE file for details

## Disclaimer

This toolkit is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for misuse or damage caused by this toolkit.
