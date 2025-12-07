---
name: Ghidra
description: Automated binary analysis using Ghidra for IoT firmware reverse engineering. Use when you need to decompile binaries, find vulnerabilities, analyze dangerous function calls, extract strings, or understand firmware behavior from extracted filesystems.
---

# Ghidra - Automated IoT Firmware Binary Analysis

You are helping the user analyze IoT firmware binaries using Ghidra for security vulnerability discovery, reverse engineering, and understanding device behavior.

## Tool Overview

This skill automates Ghidra binary analysis to eliminate manual steps in the IoT pentesting workflow. It integrates with the `ffind` skill workflow - after extracting filesystems from firmware, use this skill to automatically analyze the extracted binaries.

**Key capabilities:**
- Automatic decompilation to pseudo-C code
- Detection of dangerous function calls (strcpy, system, sprintf, etc.)
- String extraction with pattern matching for credentials, IPs, URLs
- Cross-reference analysis to trace data/control flow
- Function signature and call graph analysis
- Support for common IoT architectures (ARM, MIPS, x86)

## Prerequisites

**Required:**
- Python 3.8+
- Ghidra 11.0+ installed
- PyGhidra: `pip install pyghidra`

**Environment Setup:**
```bash
# Set Ghidra path (choose one method)
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.0

# Or pass via command line
ghidra firmware.bin --action quick --ghidra-path /path/to/ghidra_11.0
```

## Instructions

When the user asks to analyze binaries, find vulnerabilities, or reverse engineer firmware:

1. **Understand the target**:
   - Ask what binary they want to analyze
   - Determine if they want quick triage or deep analysis
   - Ask about specific functions or patterns of interest

2. **Execute the analysis**:
   - Use the ghidra command from the iothackbot bin directory
   - Basic usage: `ghidra <binary> --action <action>`
   - Available actions: quick, analyze, dangerous, decompile, strings, xrefs

3. **Output formats**:
   - `--format text` (default): Human-readable colored output
   - `--format json`: Machine-readable JSON
   - `--format quiet`: Minimal output

## Examples

Quick security triage (recommended starting point):
```bash
ghidra /path/to/firmware.bin --action quick
```

Find functions calling dangerous APIs:
```bash
ghidra /path/to/httpd --action dangerous
```

Decompile specific function:
```bash
ghidra /path/to/binary --action decompile --function main
```

Decompile function at address:
```bash
ghidra /path/to/binary --action decompile --address 0x00401000
```

Search for strings matching pattern:
```bash
ghidra /path/to/binary --action strings --pattern "password"
```

Find all interesting strings (credentials, IPs, paths):
```bash
ghidra /path/to/binary --action strings
```

Get cross-references to function:
```bash
ghidra /path/to/binary --action xrefs --function strcpy
```

Full analysis with all functions:
```bash
ghidra /path/to/binary --action analyze --format json -o analysis.json
```

## Common Workflows

### Workflow 1: Web Server Vulnerability Analysis

IoT devices often run embedded web servers. Analyze for command injection:

```bash
# 1. Quick triage
ghidra /tmp/fw/usr/bin/httpd --action quick

# 2. Find command execution
ghidra /tmp/fw/usr/bin/httpd --action dangerous

# 3. Decompile suspicious handlers
ghidra /tmp/fw/usr/bin/httpd --action decompile --function handle_cgi

# 4. Trace user input handling
ghidra /tmp/fw/usr/bin/httpd --action xrefs --function getenv
```

### Workflow 2: Credential Discovery

Find hardcoded credentials in firmware:

```bash
# 1. Search for password-related strings
ghidra /tmp/fw/usr/bin/mgmt --action strings --pattern "password|passwd|secret"

# 2. Check for default accounts
ghidra /tmp/fw/usr/bin/mgmt --action strings --pattern "admin|root|user"

# 3. Find authentication functions
ghidra /tmp/fw/usr/bin/mgmt --action dangerous

# 4. Decompile auth logic
ghidra /tmp/fw/usr/bin/mgmt --action decompile --function check_password
```

### Workflow 3: Integration with ffind

After extracting firmware filesystem:

```bash
# 1. Extract firmware filesystem
sudo ffind /path/to/firmware.bin -e -d /tmp/extracted

# 2. Identify interesting binaries
find /tmp/extracted -type f -executable | head -10

# 3. Quick triage of key binaries
ghidra /tmp/extracted/usr/bin/httpd --action quick
```

## Important Notes

- PyGhidra is required for automated analysis
- First analysis of a binary takes longer (Ghidra auto-analysis runs)
- Subsequent queries on the same binary are faster if project is cached
- JSON output is designed for automation - use `--format json` for scripting
- Always combine with dynamic analysis when possible
- Extraction requires root/sudo privileges
