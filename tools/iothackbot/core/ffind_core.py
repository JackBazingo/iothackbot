"""
Core ffind functionality - file type analysis and extraction.
Separated from CLI logic for automation and chaining.
"""

import os
import zipfile
import datetime
from typing import List, Tuple, Dict, Any
from .interfaces import ToolInterface, ToolConfig, ToolResult

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False


def enumerate_files(input_path: str) -> List[Tuple[str, str]]:
    """Recursively enumerate files, returning (file_path, relative_path) pairs."""
    file_list = []
    if os.path.isfile(input_path):
        if os.path.islink(input_path):
            return []  # Skip symlinks
        try:
            size = os.path.getsize(input_path)
            file_list = [(input_path, os.path.basename(input_path))]
        except OSError:
            return []
        start_path = os.path.dirname(input_path) or '.'
        return [(input_path, os.path.relpath(input_path, start_path))]
    elif os.path.isdir(input_path):
        start_path = input_path
        for root, dirs, filenames in os.walk(input_path):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                if os.path.islink(file_path):
                    continue  # Ignore symlinks
                if not os.path.isfile(file_path):
                    continue  # Ensure it's a regular file
                try:
                    size = os.path.getsize(file_path)
                    rel_path = os.path.relpath(file_path, start_path)
                    file_list.append((file_path, rel_path))
                except OSError:
                    continue  # Skip files we can't access
    else:
        raise ValueError("Invalid input path")

    # Sort by size ascending (quicker initial progress)
    file_list.sort(key=lambda x: os.path.getsize(x[0]))
    return file_list


# Modular extraction: Dict of MIME types to extractor functions
EXTRACTORS = {
    'application/java-archive': lambda fp, base_dir: extract_jar(fp, base_dir),
    # Add more here, e.g., 'application/zip': extract_zip, etc.
}

# Special extractors based on file description (for types not properly detected by MIME)
DESCRIPTION_EXTRACTORS = {
    'ext4': lambda fp, base_dir: extract_ext4(fp, base_dir),
    'f2fs': lambda fp, base_dir: extract_f2fs(fp, base_dir),
}

ARTIFACT_FILES = {
    'text/x-ssl-private-key',
    'application/java-archive',
    'application/x-pem-file'
}


def is_extractable(file_type: str, description: str = "") -> bool:
    """Check if file type has a registered extractor."""
    # Check MIME type extractors
    if file_type in EXTRACTORS:
        return True

    # Check description-based extractors
    description_lower = description.lower()
    for desc_key in DESCRIPTION_EXTRACTORS:
        if desc_key in description_lower:
            return True

    return False


def extract_jar(file_path: str, base_extract_dir: str) -> bool:
    """Extractor for JAR files: Unzip to a subdir in the base extract dir."""
    try:
        # Create unique subdir for this file (basename + '_extracted')
        basename = os.path.basename(file_path)
        sub_extract_dir = os.path.join(base_extract_dir, f"{basename}_extracted")
        os.makedirs(sub_extract_dir, exist_ok=True)

        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(sub_extract_dir)

        return True
    except Exception:
        return False


def extract_ext4(file_path: str, base_extract_dir: str) -> bool:
    """Extractor for ext4 filesystem images: Mount and copy contents."""
    import subprocess
    import tempfile
    import shutil

    try:
        # Create unique subdir for this file (basename + '_extracted')
        basename = os.path.basename(file_path)
        sub_extract_dir = os.path.join(base_extract_dir, f"{basename}_extracted")
        os.makedirs(sub_extract_dir, exist_ok=True)

        # Create a temporary mount point and work on a copy to avoid modifying original
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_mount = os.path.join(temp_dir, 'mount')
            os.makedirs(temp_mount)

            # Create a copy of the filesystem image to work with
            temp_image = os.path.join(temp_dir, 'image.bin')
            shutil.copy2(file_path, temp_image)

            try:
                # Try to repair the filesystem copy
                try:
                    subprocess.run(
                        ['sudo', 'e2fsck', '-y', temp_image],
                        capture_output=True, timeout=30
                    )
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    pass  # Continue even if fsck fails

                # Set up loop device on the copy
                loop_setup = subprocess.run(
                    ['sudo', 'losetup', '-f', '--show', temp_image],
                    capture_output=True, text=True, check=True
                )
                loop_device = loop_setup.stdout.strip()

                try:
                    # Try mounting with recovery options
                    mount_cmd = ['sudo', 'mount', '-t', 'ext4', '-o', 'ro,noload', loop_device, temp_mount]
                    subprocess.run(mount_cmd, check=True, capture_output=True)

                    try:
                        # Copy contents (excluding special files and directories)
                        items = os.listdir(temp_mount)
                        valid_items = [item for item in items if not (item.startswith('.') or item == 'lost+found')]
                        if not valid_items:
                            # Only special directories found, fall back to debugfs
                            return extract_ext4_debugfs(file_path, sub_extract_dir)

                        for item in valid_items:
                            src_path = os.path.join(temp_mount, item)
                            dst_path = os.path.join(sub_extract_dir, item)

                            # Skip lost+found and other special directories
                            if item.startswith('.') or item == 'lost+found':
                                continue

                            try:
                                if os.path.isfile(src_path):
                                    shutil.copy2(src_path, dst_path)
                                elif os.path.isdir(src_path):
                                    shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
                            except (OSError, shutil.Error):
                                # Skip files that can't be copied
                                continue

                        return True
                    finally:
                        # Unmount
                        subprocess.run(['sudo', 'umount', temp_mount], check=False)

                finally:
                    # Clean up loop device
                    subprocess.run(['sudo', 'losetup', '-d', loop_device], check=False)

            except subprocess.CalledProcessError:
                # If mounting fails, try alternative approach with debugfs
                return extract_ext4_debugfs(file_path, sub_extract_dir)

    except Exception:
        return False


def extract_ext4_debugfs(file_path: str, extract_dir: str) -> bool:
    """Alternative ext4 extraction using debugfs (read-only, no mount required)."""
    import subprocess
    import tempfile

    try:
        # Create a basic info file
        info_file = os.path.join(extract_dir, 'filesystem_info.txt')
        with open(info_file, 'w') as f:
            f.write(f"ext4 filesystem image: {os.path.basename(file_path)}\n")
            f.write("Extracted using debugfs.\n\n")

        # Get filesystem listing
        try:
            result = subprocess.run(
                ['sudo', 'debugfs', '-R', 'ls -l /', file_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                with open(info_file, 'a') as f:
                    f.write("Filesystem contents:\n")
                    f.write(result.stdout)
                    f.write("\n")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass

        # Try to extract some key files using debugfs
        files_to_extract = ['ipnc.log', 'syslog']
        for filename in files_to_extract:
            try:
                extracted_path = os.path.join(extract_dir, filename)
                dump_cmd = ['sudo', 'debugfs', '-R', f'dump /{filename} {extracted_path}', file_path]
                result = subprocess.run(dump_cmd, capture_output=True, timeout=30)

                if result.returncode != 0:
                    # Try alternative syntax
                    dump_cmd2 = ['sudo', 'debugfs', file_path, '-f', '/dev/stdin']
                    result2 = subprocess.run(
                        dump_cmd2,
                        input=f'dump /{filename} {extracted_path}\nquit\n',
                        text=True,
                        capture_output=True,
                        timeout=30
                    )
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError):
                continue

        return True

    except Exception:
        return False


def extract_f2fs(file_path: str, base_extract_dir: str) -> bool:
    """Extractor for F2FS filesystem images: Mount and copy contents."""
    import subprocess
    import tempfile
    import shutil

    try:
        # Create unique subdir for this file (basename + '_extracted')
        basename = os.path.basename(file_path)
        sub_extract_dir = os.path.join(base_extract_dir, f"{basename}_extracted")
        os.makedirs(sub_extract_dir, exist_ok=True)

        # Create a temporary mount point and work on a copy to avoid modifying original
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_mount = os.path.join(temp_dir, 'mount')
            os.makedirs(temp_mount)

            # Create a copy of the filesystem image to work with
            temp_image = os.path.join(temp_dir, 'image.bin')
            shutil.copy2(file_path, temp_image)

            try:
                # Try to repair the filesystem copy
                try:
                    subprocess.run(
                        ['sudo', 'fsck.f2fs', '-y', temp_image],
                        capture_output=True, timeout=30
                    )
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    pass  # Continue even if fsck fails

                # Set up loop device on the copy
                loop_setup = subprocess.run(
                    ['sudo', 'losetup', '-f', '--show', temp_image],
                    capture_output=True, text=True, check=True
                )
                loop_device = loop_setup.stdout.strip()

                try:
                    # Try mounting with recovery options
                    mount_cmd = ['sudo', 'mount', '-t', 'f2fs', '-o', 'ro', loop_device, temp_mount]
                    subprocess.run(mount_cmd, check=True, capture_output=True)

                    try:
                        # Copy contents (excluding special files and directories)
                        items = os.listdir(temp_mount)
                        valid_items = [item for item in items if not (item.startswith('.') or item == 'lost+found')]
                        if not valid_items:
                            # Only special directories found, fall back to dump.f2fs
                            return extract_f2fs_dump(file_path, sub_extract_dir)

                        for item in valid_items:
                            src_path = os.path.join(temp_mount, item)
                            dst_path = os.path.join(sub_extract_dir, item)

                            # Skip lost+found and other special directories
                            if item.startswith('.') or item == 'lost+found':
                                continue

                            try:
                                if os.path.isfile(src_path):
                                    shutil.copy2(src_path, dst_path)
                                elif os.path.isdir(src_path):
                                    shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
                            except (OSError, shutil.Error):
                                # Skip files that can't be copied
                                continue

                        return True
                    finally:
                        # Unmount
                        subprocess.run(['sudo', 'umount', temp_mount], check=False)

                finally:
                    # Clean up loop device
                    subprocess.run(['sudo', 'losetup', '-d', loop_device], check=False)

            except subprocess.CalledProcessError:
                # If mounting fails, try alternative approach with dump.f2fs
                return extract_f2fs_dump(file_path, sub_extract_dir)

    except Exception:
        return False


def extract_f2fs_dump(file_path: str, extract_dir: str) -> bool:
    """Alternative F2FS extraction using dump.f2fs (read-only, no mount required)."""
    import subprocess
    import tempfile

    try:
        # Create a basic info file
        info_file = os.path.join(extract_dir, 'filesystem_info.txt')
        with open(info_file, 'w') as f:
            f.write(f"F2FS filesystem image: {os.path.basename(file_path)}\n")
            f.write("Extracted using dump.f2fs.\n\n")

        # Get filesystem listing using dump.f2fs
        try:
            result = subprocess.run(
                ['sudo', 'dump.f2fs', '-l', file_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                with open(info_file, 'a') as f:
                    f.write("Filesystem contents:\n")
                    f.write(result.stdout)
                    f.write("\n")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass

        # Try to extract some key files using dump.f2fs
        files_to_extract = ['ipnc.log', 'syslog', 'messages', 'auth.log']
        for filename in files_to_extract:
            try:
                extracted_path = os.path.join(extract_dir, filename)
                dump_cmd = ['sudo', 'dump.f2fs', '-f', f'/{filename}', file_path, extracted_path]
                result = subprocess.run(dump_cmd, capture_output=True, timeout=30)

                if result.returncode != 0:
                    # Try alternative syntax
                    dump_cmd2 = ['sudo', 'dump.f2fs', '-f', f'/{filename}', file_path]
                    result2 = subprocess.run(
                        dump_cmd2,
                        stdout=open(extracted_path, 'w'),
                        stderr=subprocess.PIPE,
                        timeout=30
                    )
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError):
                continue

        return True

    except Exception:
        return False


def analyze_files(file_list: List[Tuple[str, str]], extract_dir: str = None) -> Dict[str, Any]:
    """Analyze files for types and optionally extract supported formats."""
    if not HAS_MAGIC:
        return {'error': 'python-magic not available'}

    type_dict = {}  # Group by type for analysis summary
    extracted_files = []
    detection_failures = []

    # Create two magic objects: one for descriptive text, one for MIME types
    mime_descriptive = magic.Magic(mime=False)  # Descriptive text
    mime_type = magic.Magic(mime=True)  # MIME type

    for fp, rel_path in file_list:
        try:
            file_description = mime_descriptive.from_file(fp)
            file_mime = mime_type.from_file(fp)

            # Use MIME type as primary key for grouping, but store both
            file_info = {
                'description': file_description,
                'mime_type': file_mime,
                'path': rel_path
            }

            if file_mime not in type_dict:
                type_dict[file_mime] = []
            type_dict[file_mime].append(file_info)

            # Extraction if enabled and type supported
            if extract_dir and is_extractable(file_mime, file_description):
                extracted = False

                # Try MIME-based extraction first
                if file_mime in EXTRACTORS:
                    extractor_func = EXTRACTORS[file_mime]
                    extracted = extractor_func(fp, extract_dir)

                # Try description-based extraction
                else:
                    description_lower = file_description.lower()
                    for desc_key, extractor_func in DESCRIPTION_EXTRACTORS.items():
                        if desc_key in description_lower:
                            extracted = extractor_func(fp, extract_dir)
                            break

                if extracted:
                    extracted_files.append(rel_path)

        except Exception:
            detection_failures.append(rel_path)

    return {
        'type_summary': type_dict,
        'extracted_files': extracted_files,
        'detection_failures': detection_failures,
        'total_files': len(file_list)
    }


class FfindTool(ToolInterface):
    """Ffind tool implementation."""

    @property
    def name(self) -> str:
        return "ffind"

    @property
    def description(self) -> str:
        return "File finder with type analysis and optional extraction"

    def run(self, config: ToolConfig) -> ToolResult:
        """Execute ffind analysis."""
        import time
        start_time = time.time()

        try:
            # Enumerate files from all input paths
            file_list = []
            for input_path in config.input_paths:
                path_files = enumerate_files(input_path)
                file_list.extend(path_files)

            if not file_list:
                return ToolResult(
                    success=False,
                    data=None,
                    errors=['No valid files found'],
                    metadata={},
                    execution_time=time.time() - start_time
                )

            # Set up extraction directory if needed
            extract_dir = None
            do_extract = config.custom_args.get('extract', False)
            if do_extract:
                custom_dir = config.custom_args.get('directory')
                if custom_dir:
                    extract_dir = custom_dir
                else:
                    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
                    extract_dir = f"/tmp/ffind-extract-{timestamp}"
                os.makedirs(extract_dir, exist_ok=True)

            # Analyze files
            analysis_result = analyze_files(file_list, extract_dir)

            if 'error' in analysis_result:
                return ToolResult(
                    success=False,
                    data=None,
                    errors=[analysis_result['error']],
                    metadata={},
                    execution_time=time.time() - start_time
                )

            execution_time = time.time() - start_time

            return ToolResult(
                success=True,
                data=analysis_result,
                errors=[],
                metadata={
                    'total_files': analysis_result['total_files'],
                    'unique_types': len(analysis_result['type_summary']),
                    'extracted_count': len(analysis_result['extracted_files']),
                    'extraction_dir': extract_dir,
                    'detection_failures': len(analysis_result['detection_failures'])
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
