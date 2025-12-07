"""
Core ghidra functionality - binary analysis and decompilation.
Separated from CLI logic for automation and chaining.
"""

import os
import re
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from .interfaces import ToolInterface, ToolConfig, ToolResult

try:
    import pyghidra
    HAS_PYGHIDRA = True
except ImportError:
    HAS_PYGHIDRA = False


# Dangerous functions commonly exploited in IoT firmware
DANGEROUS_FUNCTIONS = [
    # Memory unsafe functions
    'strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'snprintf',
    'vsprintf', 'vsnprintf', 'gets', 'fgets', 'scanf', 'fscanf',
    'sscanf', 'vscanf', 'vfscanf', 'vsscanf', 'memcpy', 'memmove',
    'bcopy', 'wcscpy', 'wcscat',
    # Command execution
    'system', 'exec', 'execl', 'execle', 'execlp', 'execv', 'execve',
    'execvp', 'popen', 'pclose', 'fork', 'vfork', 'clone',
    'dlopen', 'dlsym',
    # File operations
    'fopen', 'open', 'creat', 'chmod', 'chown', 'unlink', 'remove',
    'rename', 'mkdir', 'rmdir', 'symlink', 'link',
    # Network operations
    'socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv',
    'sendto', 'recvfrom', 'gethostbyname', 'getaddrinfo',
    # Crypto (weak or misused)
    'rand', 'srand', 'random', 'srandom', 'crypt', 'DES_', 'MD5',
    # Format string vulnerabilities
    'printf', 'fprintf', 'dprintf', 'vprintf', 'vfprintf',
    # IoT-specific
    'nvram_get', 'nvram_set', 'httpd', 'uci_get', 'uci_set',
]

# Interesting strings for IoT analysis
INTERESTING_PATTERNS = [
    r'password', r'passwd', r'secret', r'credential', r'token',
    r'api.?key', r'auth', r'login', r'admin', r'root', r'user',
    r'default', r'backdoor', r'master', r'debug', r'test',
    r'http://', r'https://', r'ftp://', r'telnet://', r'ssh://',
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    r'/etc/', r'/tmp/', r'/var/', r'/dev/', r'/proc/',
    r'/bin/sh', r'/bin/bash', r'busybox', r'telnetd', r'dropbear',
]


def find_ghidra(ghidra_path: Optional[str] = None) -> Optional[Path]:
    """Find Ghidra installation directory."""
    if ghidra_path:
        return Path(ghidra_path)

    # Check environment variable
    env_path = os.environ.get('GHIDRA_INSTALL_DIR')
    if env_path and Path(env_path).exists():
        return Path(env_path)

    # Common installation paths
    common_paths = [
        Path.home() / 'ghidra',
        Path('/opt/ghidra'),
        Path('/usr/share/ghidra'),
        Path('/usr/local/ghidra'),
        Path('C:/ghidra'),
        Path('C:/Program Files/ghidra'),
    ]

    for base in common_paths:
        if base.exists():
            for child in base.iterdir():
                if child.is_dir() and child.name.startswith('ghidra_'):
                    return child
            if (base / 'support' / 'analyzeHeadless').exists():
                return base

    return None


def get_program_info(program) -> Dict[str, str]:
    """Extract program metadata from Ghidra program object."""
    return {
        'name': program.getName(),
        'language': str(program.getLanguage()),
        'compiler': str(program.getCompilerSpec()),
        'image_base': str(program.getImageBase()),
        'executable_format': program.getExecutableFormat(),
    }


def extract_function_data(func, monitor) -> Dict[str, Any]:
    """Extract function information from Ghidra function object."""
    func_data = {
        'name': func.getName(),
        'address': str(func.getEntryPoint()),
        'signature': str(func.getSignature()),
        'is_thunk': func.isThunk(),
        'is_external': func.isExternal(),
        'callers': [],
        'callees': [],
        'calls_dangerous': False,
        'dangerous_calls': [],
    }

    try:
        for caller in func.getCallingFunctions(monitor):
            func_data['callers'].append(caller.getName())
        for callee in func.getCalledFunctions(monitor):
            callee_name = callee.getName()
            func_data['callees'].append(callee_name)
            if callee_name in DANGEROUS_FUNCTIONS:
                func_data['calls_dangerous'] = True
                func_data['dangerous_calls'].append(callee_name)
    except Exception:
        pass

    return func_data


def extract_strings(program, limit: int = 500) -> List[Dict[str, str]]:
    """Extract defined strings from program."""
    from ghidra.program.util import DefinedDataIterator

    strings = []
    count = 0

    for data in DefinedDataIterator.definedStrings(program):
        if count >= limit:
            break
        try:
            value = str(data.getValue())
            if len(value) >= 4:
                strings.append({
                    'address': str(data.getAddress()),
                    'value': value[:500],
                    'length': len(value),
                })
                count += 1
        except Exception:
            pass

    return strings


def extract_imports(program) -> List[Dict[str, str]]:
    """Extract imported symbols from program."""
    imports = []
    symbol_table = program.getSymbolTable()

    for symbol in symbol_table.getExternalSymbols():
        imports.append({
            'name': symbol.getName(),
            'address': str(symbol.getAddress()),
            'namespace': str(symbol.getParentNamespace()),
        })

    return imports


def extract_exports(program) -> List[Dict[str, str]]:
    """Extract exported symbols from program."""
    exports = []
    symbol_table = program.getSymbolTable()

    for symbol in symbol_table.getAllSymbols(True):
        if symbol.isExternalEntryPoint():
            exports.append({
                'name': symbol.getName(),
                'address': str(symbol.getAddress()),
            })

    return exports


def analyze_binary(binary_path: str) -> Dict[str, Any]:
    """Perform full analysis of binary using PyGhidra."""
    if not HAS_PYGHIDRA:
        return {'error': 'pyghidra not available'}

    from datetime import datetime
    from ghidra.util.task import ConsoleTaskMonitor

    try:
        pyghidra.start()

        with pyghidra.open_program(binary_path) as flat_api:
            program = flat_api.getCurrentProgram()
            monitor = ConsoleTaskMonitor()

            results = {
                'binary': binary_path,
                'timestamp': datetime.now().isoformat(),
                'analysis_method': 'pyghidra',
                'program_info': get_program_info(program),
                'functions': [],
                'dangerous_functions': [],
                'strings': [],
                'imports': [],
                'exports': [],
            }

            func_mgr = program.getFunctionManager()

            for func in func_mgr.getFunctions(True):
                func_data = extract_function_data(func, monitor)
                results['functions'].append(func_data)

                if func_data.get('calls_dangerous'):
                    results['dangerous_functions'].append(func_data)

            results['strings'] = extract_strings(program)
            results['imports'] = extract_imports(program)
            results['exports'] = extract_exports(program)

            results['summary'] = {
                'total_functions': len(results['functions']),
                'dangerous_function_count': len(results['dangerous_functions']),
                'total_strings': len(results['strings']),
                'imports_count': len(results['imports']),
                'exports_count': len(results['exports']),
            }

            return results

    except Exception as e:
        return {
            'error': str(e),
            'binary': binary_path,
            'analysis_method': 'pyghidra',
        }


def find_dangerous_functions(binary_path: str) -> Dict[str, Any]:
    """Find all functions that call dangerous APIs."""
    results = analyze_binary(binary_path)
    if 'error' in results:
        return results

    return {
        'binary': binary_path,
        'dangerous_functions': results.get('dangerous_functions', []),
        'total_found': len(results.get('dangerous_functions', [])),
        'dangerous_api_list': DANGEROUS_FUNCTIONS[:20],
    }


def decompile_function(binary_path: str, func_name: str = None,
                       address: str = None) -> Dict[str, Any]:
    """Decompile a specific function."""
    if not HAS_PYGHIDRA:
        return {'error': 'pyghidra required for decompilation'}

    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor

    try:
        pyghidra.start()

        with pyghidra.open_program(binary_path) as flat_api:
            program = flat_api.getCurrentProgram()
            func_mgr = program.getFunctionManager()

            target_func = None

            if func_name:
                for func in func_mgr.getFunctions(True):
                    if func.getName() == func_name:
                        target_func = func
                        break

            if address and not target_func:
                addr_factory = program.getAddressFactory()
                try:
                    addr = addr_factory.getAddress(address)
                    target_func = func_mgr.getFunctionAt(addr)
                except Exception:
                    pass

            if not target_func:
                return {
                    'error': f'Function not found: {func_name or address}',
                    'available_functions': [
                        f.getName() for f in list(func_mgr.getFunctions(True))[:50]
                    ]
                }

            ifc = DecompInterface()
            ifc.setOptions(DecompileOptions())
            ifc.openProgram(program)

            monitor = ConsoleTaskMonitor()
            result = ifc.decompileFunction(target_func, 60, monitor)

            if result.decompileCompleted():
                decomp_func = result.getDecompiledFunction()
                return {
                    'function_name': target_func.getName(),
                    'address': str(target_func.getEntryPoint()),
                    'signature': str(target_func.getSignature()),
                    'decompiled_c': decomp_func.getC(),
                    'success': True,
                }
            else:
                return {
                    'function_name': target_func.getName(),
                    'address': str(target_func.getEntryPoint()),
                    'error': 'Decompilation failed',
                    'success': False,
                }

    except Exception as e:
        return {'error': str(e), 'success': False}


def search_strings(binary_path: str, pattern: str = None) -> Dict[str, Any]:
    """Search for strings in the binary."""
    if not HAS_PYGHIDRA:
        return {'error': 'pyghidra required for string search'}

    try:
        pyghidra.start()

        with pyghidra.open_program(binary_path) as flat_api:
            program = flat_api.getCurrentProgram()
            all_strings = extract_strings(program, limit=2000)

            if pattern:
                regex = re.compile(pattern, re.IGNORECASE)
                matching = [s for s in all_strings if regex.search(s['value'])]
            else:
                matching = all_strings

            interesting = []
            for s in all_strings:
                for p in INTERESTING_PATTERNS:
                    if re.search(p, s['value'], re.IGNORECASE):
                        s['matched_pattern'] = p
                        interesting.append(s)
                        break

            return {
                'binary': binary_path,
                'total_strings': len(all_strings),
                'matching_strings': matching if pattern else None,
                'interesting_strings': interesting,
                'search_pattern': pattern,
            }

    except Exception as e:
        return {'error': str(e)}


def get_xrefs(binary_path: str, address: str = None,
              func_name: str = None) -> Dict[str, Any]:
    """Get cross-references to/from an address or function."""
    if not HAS_PYGHIDRA:
        return {'error': 'pyghidra required for xref analysis'}

    try:
        pyghidra.start()

        with pyghidra.open_program(binary_path) as flat_api:
            program = flat_api.getCurrentProgram()
            ref_mgr = program.getReferenceManager()

            target_addr = None

            if address:
                addr_factory = program.getAddressFactory()
                target_addr = addr_factory.getAddress(address)
            elif func_name:
                func_mgr = program.getFunctionManager()
                for func in func_mgr.getFunctions(True):
                    if func.getName() == func_name:
                        target_addr = func.getEntryPoint()
                        break

            if not target_addr:
                return {'error': f'Target not found: {address or func_name}'}

            refs_to = []
            refs_from = []

            for ref in ref_mgr.getReferencesTo(target_addr):
                refs_to.append({
                    'from_address': str(ref.getFromAddress()),
                    'ref_type': str(ref.getReferenceType()),
                })

            for ref in ref_mgr.getReferencesFrom(target_addr):
                refs_from.append({
                    'to_address': str(ref.getToAddress()),
                    'ref_type': str(ref.getReferenceType()),
                })

            return {
                'target': address or func_name,
                'target_address': str(target_addr),
                'references_to': refs_to,
                'references_from': refs_from,
                'xrefs_to_count': len(refs_to),
                'xrefs_from_count': len(refs_from),
            }

    except Exception as e:
        return {'error': str(e)}


def quick_analysis(binary_path: str) -> Dict[str, Any]:
    """Perform quick security-focused analysis."""
    from datetime import datetime

    results = {
        'binary': binary_path,
        'timestamp': datetime.now().isoformat(),
        'file_size': Path(binary_path).stat().st_size,
    }

    if not HAS_PYGHIDRA:
        results['error'] = 'pyghidra not available'
        results['hint'] = 'Install with: pip install pyghidra'
        return results

    full_analysis = analyze_binary(binary_path)

    if 'error' in full_analysis:
        results['error'] = full_analysis['error']
        return results

    results['program_info'] = full_analysis.get('program_info', {})
    results['summary'] = full_analysis.get('summary', {})

    dangerous = full_analysis.get('dangerous_functions', [])[:10]
    results['top_dangerous_functions'] = [
        {
            'name': f['name'],
            'address': f['address'],
            'dangerous_calls': f.get('dangerous_calls', []),
        }
        for f in dangerous
    ]

    interesting = []
    for s in full_analysis.get('strings', []):
        for pattern in INTERESTING_PATTERNS[:10]:
            if re.search(pattern, s['value'], re.IGNORECASE):
                interesting.append(s)
                break
        if len(interesting) >= 20:
            break
    results['interesting_strings'] = interesting

    results['priority_review'] = [f['name'] for f in dangerous[:5]]

    return results


class GhidraTool(ToolInterface):
    """Ghidra tool implementation."""

    @property
    def name(self) -> str:
        return "ghidra"

    @property
    def description(self) -> str:
        return "Binary analysis and decompilation using Ghidra"

    def run(self, config: ToolConfig) -> ToolResult:
        """Execute ghidra analysis."""
        start_time = time.time()

        try:
            if not HAS_PYGHIDRA:
                return ToolResult(
                    success=False,
                    data=None,
                    errors=['pyghidra not available - install with: pip install pyghidra'],
                    metadata={},
                    execution_time=time.time() - start_time
                )

            binary_path = config.input_path
            if not binary_path or not Path(binary_path).exists():
                return ToolResult(
                    success=False,
                    data=None,
                    errors=[f'Binary not found: {binary_path}'],
                    metadata={},
                    execution_time=time.time() - start_time
                )

            action = config.custom_args.get('action', 'quick')
            func_name = config.custom_args.get('function')
            address = config.custom_args.get('address')
            pattern = config.custom_args.get('pattern')

            if action == 'quick':
                result_data = quick_analysis(binary_path)
            elif action == 'analyze':
                result_data = analyze_binary(binary_path)
            elif action == 'dangerous':
                result_data = find_dangerous_functions(binary_path)
            elif action == 'decompile':
                if not func_name and not address:
                    return ToolResult(
                        success=False,
                        data=None,
                        errors=['Specify --function or --address for decompile'],
                        metadata={},
                        execution_time=time.time() - start_time
                    )
                result_data = decompile_function(binary_path, func_name, address)
            elif action == 'strings':
                result_data = search_strings(binary_path, pattern)
            elif action == 'xrefs':
                if not func_name and not address:
                    return ToolResult(
                        success=False,
                        data=None,
                        errors=['Specify --function or --address for xrefs'],
                        metadata={},
                        execution_time=time.time() - start_time
                    )
                result_data = get_xrefs(binary_path, address, func_name)
            else:
                return ToolResult(
                    success=False,
                    data=None,
                    errors=[f'Unknown action: {action}'],
                    metadata={},
                    execution_time=time.time() - start_time
                )

            execution_time = time.time() - start_time

            if 'error' in result_data:
                return ToolResult(
                    success=False,
                    data=result_data,
                    errors=[result_data['error']],
                    metadata={'action': action},
                    execution_time=execution_time
                )

            return ToolResult(
                success=True,
                data=result_data,
                errors=[],
                metadata={
                    'action': action,
                    'binary': binary_path,
                    'summary': result_data.get('summary', {}),
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
