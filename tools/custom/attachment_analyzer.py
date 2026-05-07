#!/usr/bin/env python3
"""
Universal Attachment Analyzer
Handles all file types that Barbarian Phishing currently ignores:
archives, scripts, executables, HTML files, LNK shortcuts, and enhanced Office checks.
"""

import io
import math
import os
import re
import struct
import zipfile
import tarfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Optional third-party imports -- degrade gracefully when missing
# ---------------------------------------------------------------------------
try:
    import puremagic
    HAS_PUREMAGIC = True
except ImportError:
    HAS_PUREMAGIC = False

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import LnkParse3
    HAS_LNKPARSE = True
except ImportError:
    HAS_LNKPARSE = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


class UniversalAttachmentAnalyzer:
    """Analyze attachment types the core email analyzer does not cover."""

    # ----- extension -> handler mapping ----------------------------------
    ARCHIVE_EXTS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.tar.gz'}
    SCRIPT_EXTS = {'.js', '.vbs', '.ps1', '.bat', '.cmd', '.wsf', '.hta'}
    EXECUTABLE_EXTS = {'.exe', '.dll', '.scr'}
    HTML_EXTS = {'.html', '.htm'}
    LNK_EXTS = {'.lnk'}
    # Dangerous executables that may be embedded inside archives
    DANGEROUS_ARCHIVE_MEMBERS = {'.exe', '.bat', '.ps1', '.vbs', '.js', '.cmd'}

    # Size threshold: 1 GB decompressed
    MAX_DECOMPRESSED_SIZE = 1 * 1024 * 1024 * 1024

    # Compression ratio threshold for zip-bomb detection
    ZIP_BOMB_RATIO = 1000

    # ----- Script suspicious-pattern definitions -------------------------
    JS_PATTERNS: List[Dict] = [
        {'pattern': r'\beval\s*\(', 'severity': 'CRITICAL', 'desc': 'eval() call'},
        {'pattern': r'WScript\.Shell', 'severity': 'CRITICAL', 'desc': 'WScript.Shell access'},
        {'pattern': r'ActiveXObject', 'severity': 'HIGH', 'desc': 'ActiveXObject instantiation'},
        {'pattern': r'fromCharCode', 'severity': 'MEDIUM', 'desc': 'String.fromCharCode (possible obfuscation)'},
    ]

    VBS_PATTERNS: List[Dict] = [
        {'pattern': r'CreateObject', 'severity': 'HIGH', 'desc': 'CreateObject call'},
        {'pattern': r'Shell\.Run', 'severity': 'CRITICAL', 'desc': 'Shell.Run execution'},
        {'pattern': r'(?i)powershell', 'severity': 'CRITICAL', 'desc': 'PowerShell invocation'},
        {'pattern': r'\bExecute\s*\(', 'severity': 'HIGH', 'desc': 'Execute() call'},
    ]

    PS1_PATTERNS: List[Dict] = [
        {'pattern': r'(?i)Invoke-Expression|(?i)\bIEX\b', 'severity': 'CRITICAL', 'desc': 'Invoke-Expression / IEX'},
        {'pattern': r'(?i)DownloadString', 'severity': 'CRITICAL', 'desc': 'DownloadString (remote payload)'},
        {'pattern': r'(?i)-enc\b', 'severity': 'HIGH', 'desc': 'Encoded command flag'},
        {'pattern': r'(?i)\bbypass\b', 'severity': 'HIGH', 'desc': 'Execution policy bypass'},
    ]

    BAT_CMD_PATTERNS: List[Dict] = [
        {'pattern': r'(?i)\bpowershell\b', 'severity': 'HIGH', 'desc': 'PowerShell invocation'},
        {'pattern': r'(?i)\bcertutil\b', 'severity': 'HIGH', 'desc': 'certutil (download / decode)'},
        {'pattern': r'(?i)\bbitsadmin\b', 'severity': 'HIGH', 'desc': 'bitsadmin (download)'},
        {'pattern': r'(?i)\breg\s+add\b', 'severity': 'MEDIUM', 'desc': 'Registry modification'},
        {'pattern': r'(?i)\bschtasks\b', 'severity': 'MEDIUM', 'desc': 'Scheduled task creation'},
    ]

    # Suspicious PE imports
    SUSPICIOUS_IMPORTS = {
        'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
        'CreateRemoteThread', 'URLDownloadToFile', 'ShellExecute',
        'WinExec', 'IsDebuggerPresent',
    }

    # LNK: dangerous target basenames
    LNK_DANGEROUS_TARGETS = {
        'cmd', 'cmd.exe', 'powershell', 'powershell.exe',
        'wscript', 'wscript.exe', 'cscript', 'cscript.exe',
        'mshta', 'mshta.exe', 'regsvr32', 'regsvr32.exe',
        'rundll32', 'rundll32.exe',
    }

    LNK_DANGEROUS_ARG_PATTERNS = [
        r'(?i)-enc\b', r'(?i)\bhidden\b', r'(?i)\bbypass\b',
        r'(?i)downloadstring', r'(?i)invoke-',
    ]

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def analyze(self, filepath: Path) -> Dict:
        """Main entry -- dispatch by file extension to the correct sub-analyzer."""
        filepath = Path(filepath)
        result = self._base_result()

        # Always validate magic bytes first
        validation = self.validate_file_type(filepath)
        result['findings'].extend(validation.get('findings', []))
        result['tools_used'].extend(validation.get('tools_used', []))

        ext = filepath.suffix.lower()
        # Handle double-extensions like .tar.gz
        if filepath.name.lower().endswith('.tar.gz') or filepath.name.lower().endswith('.tgz'):
            ext = '.tar.gz'

        try:
            if ext in self.ARCHIVE_EXTS:
                sub = self._analyze_archive(filepath)
            elif ext in self.SCRIPT_EXTS:
                sub = self._analyze_script(filepath)
            elif ext in self.EXECUTABLE_EXTS:
                sub = self._analyze_executable(filepath)
            elif ext in self.HTML_EXTS:
                sub = self._analyze_html_file(filepath)
            elif ext in self.LNK_EXTS:
                sub = self._analyze_lnk(filepath)
            else:
                sub = {
                    'findings': [{
                        'severity': 'INFO',
                        'category': 'Unsupported Type',
                        'message': f'No specialized analyzer for extension: {ext}',
                        'details': str(filepath),
                    }],
                    'tools_used': [],
                }
        except Exception as exc:
            sub = {
                'findings': [{
                    'severity': 'ERROR',
                    'category': 'Analysis Failure',
                    'message': f'Exception during analysis: {exc}',
                    'details': str(filepath),
                }],
                'tools_used': [],
            }

        result['findings'].extend(sub.get('findings', []))
        result['tools_used'].extend(sub.get('tools_used', []))
        return result

    # ------------------------------------------------------------------
    # Magic-byte validation
    # ------------------------------------------------------------------
    def validate_file_type(self, filepath: Path) -> Dict:
        """Check magic bytes vs extension using puremagic.  Flag mismatches."""
        findings: List[Dict] = []
        tools_used: List[Dict] = []

        if not HAS_PUREMAGIC:
            tools_used.append({
                'name': 'puremagic',
                'status': 'unavailable',
                'type': 'custom',
                'timestamp': datetime.now().isoformat(),
            })
            findings.append({
                'severity': 'INFO',
                'category': 'Dependency Missing',
                'message': 'puremagic not installed -- magic-byte validation skipped',
                'details': 'Install with: pip install puremagic',
            })
            return {'findings': findings, 'tools_used': tools_used}

        try:
            detected_ext = puremagic.from_file(str(filepath))
            declared_ext = filepath.suffix.lower()

            tools_used.append({
                'name': 'puremagic',
                'status': 'success',
                'type': 'custom',
                'timestamp': datetime.now().isoformat(),
            })

            # Normalize for comparison (puremagic may return e.g. ".jpeg" for ".jpg")
            equivalent_groups = [
                {'.jpg', '.jpeg'},
                {'.tgz', '.tar.gz', '.gz'},
                {'.htm', '.html'},
                {'.doc', '.xls', '.ppt', '.msi'},  # all compound-document
                {'.docx', '.xlsx', '.pptx', '.zip', '.jar', '.odt', '.ods'},
            ]
            match = False
            for group in equivalent_groups:
                if detected_ext in group and declared_ext in group:
                    match = True
                    break
            if not match and detected_ext == declared_ext:
                match = True

            if not match:
                findings.append({
                    'severity': 'HIGH',
                    'category': 'File Type Mismatch',
                    'message': (
                        f'Magic bytes indicate "{detected_ext}" but extension '
                        f'is "{declared_ext}"'
                    ),
                    'details': (
                        'The file content does not match its declared extension. '
                        'This could indicate a disguised file.'
                    ),
                })
        except puremagic.PureError:
            tools_used.append({
                'name': 'puremagic',
                'status': 'success',
                'type': 'custom',
                'timestamp': datetime.now().isoformat(),
            })
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Unknown File Type',
                'message': 'Could not determine file type from magic bytes',
                'details': str(filepath),
            })
        except Exception as exc:
            tools_used.append({
                'name': 'puremagic',
                'status': 'error',
                'type': 'custom',
                'timestamp': datetime.now().isoformat(),
            })
            findings.append({
                'severity': 'INFO',
                'category': 'Validation Error',
                'message': f'Magic-byte validation failed: {exc}',
                'details': str(filepath),
            })

        return {'findings': findings, 'tools_used': tools_used}

    # ------------------------------------------------------------------
    # Archive analysis
    # ------------------------------------------------------------------
    def _analyze_archive(self, filepath: Path) -> Dict:
        """Analyze .zip, .rar, .7z, .tar, .gz archives."""
        findings: List[Dict] = []
        tools_used: List[Dict] = []
        ext = filepath.suffix.lower()

        # Handle double extension
        if filepath.name.lower().endswith('.tar.gz') or filepath.name.lower().endswith('.tgz'):
            ext = '.tar.gz'

        # ----- ZIP -----
        if ext == '.zip':
            try:
                with zipfile.ZipFile(str(filepath), 'r') as zf:
                    total_decompressed = 0

                    for info in zf.infolist():
                        name = info.filename
                        compressed = info.compress_size or 1
                        decompressed = info.file_size

                        total_decompressed += decompressed

                        # Compression ratio check (zip bomb)
                        if compressed > 0 and decompressed / compressed > self.ZIP_BOMB_RATIO:
                            findings.append({
                                'severity': 'CRITICAL',
                                'category': 'Zip Bomb',
                                'message': (
                                    f'Extreme compression ratio '
                                    f'({decompressed / compressed:.0f}:1) for "{name}"'
                                ),
                                'details': (
                                    f'Compressed: {compressed} bytes, '
                                    f'Decompressed: {decompressed} bytes'
                                ),
                            })

                        # Path traversal
                        if '..' in name:
                            findings.append({
                                'severity': 'HIGH',
                                'category': 'Path Traversal',
                                'message': f'Archive member contains ".." in path: "{name}"',
                                'details': 'May attempt to write files outside the extraction directory',
                            })

                        # Executable content
                        member_ext = Path(name).suffix.lower()
                        if member_ext in self.DANGEROUS_ARCHIVE_MEMBERS:
                            findings.append({
                                'severity': 'HIGH',
                                'category': 'Executable in Archive',
                                'message': f'Archive contains executable/script: "{name}"',
                                'details': f'File type: {member_ext}',
                            })

                        # Nested archive
                        if member_ext in {'.zip', '.rar', '.7z', '.tar', '.gz', '.tgz'}:
                            findings.append({
                                'severity': 'MEDIUM',
                                'category': 'Nested Archive',
                                'message': f'Archive contains another archive: "{name}"',
                                'details': 'Nested archives may be used to evade scanning',
                            })

                    # Total decompressed size check
                    if total_decompressed > self.MAX_DECOMPRESSED_SIZE:
                        findings.append({
                            'severity': 'CRITICAL',
                            'category': 'Zip Bomb',
                            'message': (
                                f'Total decompressed size exceeds 1 GB '
                                f'({total_decompressed / (1024**3):.2f} GB)'
                            ),
                            'details': 'Possible zip bomb or resource exhaustion attack',
                        })

                tools_used.append({
                    'name': 'zipfile',
                    'status': 'success',
                    'type': 'custom',
                    'timestamp': datetime.now().isoformat(),
                })
            except zipfile.BadZipFile as exc:
                findings.append({
                    'severity': 'MEDIUM',
                    'category': 'Corrupt Archive',
                    'message': f'Invalid ZIP file: {exc}',
                    'details': str(filepath),
                })
                tools_used.append({
                    'name': 'zipfile',
                    'status': 'error',
                    'type': 'custom',
                    'timestamp': datetime.now().isoformat(),
                })
            except Exception as exc:
                findings.append({
                    'severity': 'ERROR',
                    'category': 'Analysis Error',
                    'message': f'ZIP analysis failed: {exc}',
                    'details': str(filepath),
                })
                tools_used.append({
                    'name': 'zipfile',
                    'status': 'error',
                    'type': 'custom',
                    'timestamp': datetime.now().isoformat(),
                })

        # ----- TAR / TAR.GZ / TGZ / GZ -----
        elif ext in {'.tar', '.tar.gz', '.tgz', '.gz'}:
            try:
                mode = 'r:gz' if ext in {'.tar.gz', '.tgz', '.gz'} else 'r'
                with tarfile.open(str(filepath), mode) as tf:
                    total_decompressed = 0

                    for member in tf.getmembers():
                        name = member.name
                        size = member.size
                        total_decompressed += size

                        # Path traversal
                        if '..' in name:
                            findings.append({
                                'severity': 'HIGH',
                                'category': 'Path Traversal',
                                'message': f'TAR member contains ".." in path: "{name}"',
                                'details': 'May attempt to write files outside the extraction directory',
                            })

                        # Executable content
                        member_ext = Path(name).suffix.lower()
                        if member_ext in self.DANGEROUS_ARCHIVE_MEMBERS:
                            findings.append({
                                'severity': 'HIGH',
                                'category': 'Executable in Archive',
                                'message': f'Archive contains executable/script: "{name}"',
                                'details': f'File type: {member_ext}',
                            })

                        # Nested archive
                        if member_ext in {'.zip', '.rar', '.7z', '.tar', '.gz', '.tgz'}:
                            findings.append({
                                'severity': 'MEDIUM',
                                'category': 'Nested Archive',
                                'message': f'Archive contains another archive: "{name}"',
                                'details': 'Nested archives may be used to evade scanning',
                            })

                    # Total decompressed size check
                    if total_decompressed > self.MAX_DECOMPRESSED_SIZE:
                        findings.append({
                            'severity': 'CRITICAL',
                            'category': 'Archive Bomb',
                            'message': (
                                f'Total decompressed size exceeds 1 GB '
                                f'({total_decompressed / (1024**3):.2f} GB)'
                            ),
                            'details': 'Possible archive bomb or resource exhaustion attack',
                        })

                tools_used.append({
                    'name': 'tarfile',
                    'status': 'success',
                    'type': 'custom',
                    'timestamp': datetime.now().isoformat(),
                })
            except tarfile.TarError as exc:
                findings.append({
                    'severity': 'MEDIUM',
                    'category': 'Corrupt Archive',
                    'message': f'Invalid TAR file: {exc}',
                    'details': str(filepath),
                })
                tools_used.append({
                    'name': 'tarfile',
                    'status': 'error',
                    'type': 'custom',
                    'timestamp': datetime.now().isoformat(),
                })
            except Exception as exc:
                findings.append({
                    'severity': 'ERROR',
                    'category': 'Analysis Error',
                    'message': f'TAR analysis failed: {exc}',
                    'details': str(filepath),
                })
                tools_used.append({
                    'name': 'tarfile',
                    'status': 'error',
                    'type': 'custom',
                    'timestamp': datetime.now().isoformat(),
                })

        # ----- RAR -----
        elif ext == '.rar':
            try:
                with open(str(filepath), 'rb') as f:
                    sig = f.read(7)
                # RAR5: 0x526172211A0700 ; RAR4: 0x526172211A07 (first 7 bytes)
                if sig[:6] == b'Rar!\x1a\x07':
                    findings.append({
                        'severity': 'INFO',
                        'category': 'RAR Archive',
                        'message': 'Valid RAR signature detected',
                        'details': 'Deeper content analysis requires unrar; only signature verified',
                    })
                else:
                    findings.append({
                        'severity': 'HIGH',
                        'category': 'Invalid Archive',
                        'message': 'File has .rar extension but invalid RAR signature',
                        'details': f'Signature bytes: {sig.hex()}',
                    })
                tools_used.append({
                    'name': 'rar_signature_check',
                    'status': 'success',
                    'type': 'custom',
                    'timestamp': datetime.now().isoformat(),
                })
            except Exception as exc:
                findings.append({
                    'severity': 'ERROR',
                    'category': 'Analysis Error',
                    'message': f'RAR signature check failed: {exc}',
                    'details': str(filepath),
                })
                tools_used.append({
                    'name': 'rar_signature_check',
                    'status': 'error',
                    'type': 'custom',
                    'timestamp': datetime.now().isoformat(),
                })

        # ----- 7Z -----
        elif ext == '.7z':
            try:
                with open(str(filepath), 'rb') as f:
                    sig = f.read(6)
                # 7z signature: 37 7A BC AF 27 1C
                if sig == b'7z\xbc\xaf\x27\x1c':
                    findings.append({
                        'severity': 'INFO',
                        'category': '7Z Archive',
                        'message': 'Valid 7z signature detected',
                        'details': 'Deeper content analysis requires py7zr; only signature verified',
                    })
                else:
                    findings.append({
                        'severity': 'HIGH',
                        'category': 'Invalid Archive',
                        'message': 'File has .7z extension but invalid 7z signature',
                        'details': f'Signature bytes: {sig.hex()}',
                    })
                tools_used.append({
                    'name': '7z_signature_check',
                    'status': 'success',
                    'type': 'custom',
                    'timestamp': datetime.now().isoformat(),
                })
            except Exception as exc:
                findings.append({
                    'severity': 'ERROR',
                    'category': 'Analysis Error',
                    'message': f'7z signature check failed: {exc}',
                    'details': str(filepath),
                })
                tools_used.append({
                    'name': '7z_signature_check',
                    'status': 'error',
                    'type': 'custom',
                    'timestamp': datetime.now().isoformat(),
                })

        return {'findings': findings, 'tools_used': tools_used}

    # ------------------------------------------------------------------
    # Script analysis
    # ------------------------------------------------------------------
    def _analyze_script(self, filepath: Path) -> Dict:
        """Analyze script files (.js, .vbs, .ps1, .bat, .cmd, .wsf, .hta)."""
        findings: List[Dict] = []
        tools_used: List[Dict] = []
        ext = filepath.suffix.lower()

        try:
            with open(str(filepath), 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as exc:
            return {
                'findings': [{
                    'severity': 'ERROR',
                    'category': 'Read Error',
                    'message': f'Could not read script file: {exc}',
                    'details': str(filepath),
                }],
                'tools_used': [],
            }

        # Select patterns based on extension
        if ext == '.js':
            patterns = self.JS_PATTERNS
        elif ext == '.vbs':
            patterns = self.VBS_PATTERNS
        elif ext == '.ps1':
            patterns = self.PS1_PATTERNS
        elif ext in {'.bat', '.cmd'}:
            patterns = self.BAT_CMD_PATTERNS
        elif ext in {'.wsf', '.hta'}:
            # WSF / HTA can contain both JS and VBS
            patterns = self.JS_PATTERNS + self.VBS_PATTERNS
        else:
            patterns = []

        for pat in patterns:
            matches = re.findall(pat['pattern'], content)
            if matches:
                findings.append({
                    'severity': pat['severity'],
                    'category': 'Suspicious Script Pattern',
                    'message': f'{pat["desc"]} found ({len(matches)} occurrence(s))',
                    'details': f'Pattern: {pat["pattern"]}  |  File: {filepath.name}',
                })

        # Shannon entropy on raw bytes
        raw_bytes = content.encode('utf-8', errors='ignore')
        entropy = self._calculate_entropy(raw_bytes)
        if entropy > 5.5:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Possible Obfuscation',
                'message': f'High Shannon entropy: {entropy:.2f}',
                'details': (
                    'Entropy above 5.5 may indicate obfuscated or encoded content'
                ),
            })

        tools_used.append({
            'name': 'script_pattern_analyzer',
            'status': 'success',
            'type': 'custom',
            'timestamp': datetime.now().isoformat(),
        })

        return {'findings': findings, 'tools_used': tools_used}

    # ------------------------------------------------------------------
    # Executable (PE) analysis
    # ------------------------------------------------------------------
    def _analyze_executable(self, filepath: Path) -> Dict:
        """Analyze PE executables (.exe, .dll, .scr) using pefile."""
        findings: List[Dict] = []
        tools_used: List[Dict] = []

        if not HAS_PEFILE:
            tools_used.append({
                'name': 'pefile',
                'status': 'unavailable',
                'type': 'custom',
                'timestamp': datetime.now().isoformat(),
            })
            findings.append({
                'severity': 'INFO',
                'category': 'Dependency Missing',
                'message': 'pefile not installed -- PE analysis skipped',
                'details': 'Install with: pip install pefile',
            })
            return {'findings': findings, 'tools_used': tools_used}

        try:
            pe = pefile.PE(str(filepath))

            # --- Section entropy ---
            for section in pe.sections:
                section_name = section.Name.rstrip(b'\x00').decode('utf-8', errors='replace')
                entropy = section.get_entropy()
                if entropy > 7.0:
                    findings.append({
                        'severity': 'HIGH',
                        'category': 'Packed / Encrypted Section',
                        'message': (
                            f'Section "{section_name}" has entropy {entropy:.2f}'
                        ),
                        'details': 'Entropy > 7.0 suggests the section is packed or encrypted',
                    })

            # --- Import checks ---
            has_imports = False
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        has_imports = True
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='replace')
                            if func_name in self.SUSPICIOUS_IMPORTS:
                                findings.append({
                                    'severity': 'HIGH',
                                    'category': 'Suspicious Import',
                                    'message': f'Imports {func_name} from {entry.dll.decode("utf-8", errors="replace")}',
                                    'details': (
                                        'This API is commonly used in malware for '
                                        'code injection, download, or evasion'
                                    ),
                                })

            if not has_imports:
                findings.append({
                    'severity': 'HIGH',
                    'category': 'No Imports',
                    'message': 'PE file has no imports',
                    'details': (
                        'Executables with no imports may be shellcode '
                        'or use dynamic resolution to hide API calls'
                    ),
                })

            pe.close()
            tools_used.append({
                'name': 'pefile',
                'status': 'success',
                'type': 'custom',
                'timestamp': datetime.now().isoformat(),
            })

        except pefile.PEFormatError as exc:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Invalid PE',
                'message': f'Invalid PE format: {exc}',
                'details': str(filepath),
            })
            tools_used.append({
                'name': 'pefile',
                'status': 'error',
                'type': 'custom',
                'timestamp': datetime.now().isoformat(),
            })
        except Exception as exc:
            findings.append({
                'severity': 'ERROR',
                'category': 'PE Analysis Error',
                'message': f'Error during PE analysis: {exc}',
                'details': str(filepath),
            })
            tools_used.append({
                'name': 'pefile',
                'status': 'error',
                'type': 'custom',
                'timestamp': datetime.now().isoformat(),
            })

        return {'findings': findings, 'tools_used': tools_used}

    # ------------------------------------------------------------------
    # HTML file analysis
    # ------------------------------------------------------------------
    def _analyze_html_file(self, filepath: Path) -> Dict:
        """Analyze HTML/HTM files for malicious content using BeautifulSoup."""
        findings: List[Dict] = []
        tools_used: List[Dict] = []

        if not HAS_BS4:
            tools_used.append({
                'name': 'BeautifulSoup',
                'status': 'unavailable',
                'type': 'custom',
                'timestamp': datetime.now().isoformat(),
            })
            findings.append({
                'severity': 'INFO',
                'category': 'Dependency Missing',
                'message': 'beautifulsoup4 not installed -- HTML analysis skipped',
                'details': 'Install with: pip install beautifulsoup4',
            })
            return {'findings': findings, 'tools_used': tools_used}

        try:
            with open(str(filepath), 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            soup = BeautifulSoup(content, 'html.parser')

            # --- Script tags ---
            script_tags = soup.find_all('script')
            if script_tags:
                findings.append({
                    'severity': 'HIGH',
                    'category': 'Script Tags',
                    'message': f'HTML contains {len(script_tags)} <script> tag(s)',
                    'details': 'Script tags may execute arbitrary code when opened',
                })

                # Check script content for eval / document.write
                for tag in script_tags:
                    script_text = tag.string or ''
                    if re.search(r'\beval\s*\(', script_text):
                        findings.append({
                            'severity': 'CRITICAL',
                            'category': 'JavaScript eval()',
                            'message': 'eval() found inside <script> tag',
                            'details': 'eval() can execute arbitrary code',
                        })
                    if re.search(r'document\.write', script_text):
                        findings.append({
                            'severity': 'CRITICAL',
                            'category': 'document.write()',
                            'message': 'document.write() found inside <script> tag',
                            'details': 'document.write can inject arbitrary HTML/JS',
                        })

            # --- Iframes ---
            iframes = soup.find_all('iframe')
            for iframe in iframes:
                style = (iframe.get('style') or '').lower()
                width = iframe.get('width', '')
                height = iframe.get('height', '')

                hidden = (
                    'display:none' in style.replace(' ', '')
                    or 'display: none' in style
                    or height == '0'
                    or 'height:0' in style.replace(' ', '')
                    or 'height: 0' in style
                )
                if hidden:
                    findings.append({
                        'severity': 'CRITICAL',
                        'category': 'Hidden Iframe',
                        'message': 'Hidden iframe detected (display:none or height:0)',
                        'details': f'src="{iframe.get("src", "N/A")}"',
                    })
                else:
                    findings.append({
                        'severity': 'HIGH',
                        'category': 'Iframe',
                        'message': 'Visible iframe detected',
                        'details': f'src="{iframe.get("src", "N/A")}"',
                    })

            # --- Forms with external actions ---
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                if action.startswith('http://') or action.startswith('https://'):
                    findings.append({
                        'severity': 'HIGH',
                        'category': 'External Form Action',
                        'message': f'Form submits to external URL',
                        'details': f'action="{action}"',
                    })

            # --- Meta refresh redirects ---
            metas = soup.find_all('meta')
            for meta in metas:
                http_equiv = (meta.get('http-equiv') or '').lower()
                if http_equiv == 'refresh':
                    findings.append({
                        'severity': 'HIGH',
                        'category': 'Meta Refresh Redirect',
                        'message': 'Meta refresh tag detected',
                        'details': f'content="{meta.get("content", "N/A")}"',
                    })

            # --- javascript: URIs ---
            all_tags = soup.find_all(True)
            for tag in all_tags:
                for attr_name, attr_val in (tag.attrs or {}).items():
                    # attr_val can be list (e.g. class) or string
                    vals = attr_val if isinstance(attr_val, list) else [attr_val]
                    for v in vals:
                        if isinstance(v, str) and v.strip().lower().startswith('javascript:'):
                            findings.append({
                                'severity': 'CRITICAL',
                                'category': 'JavaScript URI',
                                'message': f'javascript: URI in <{tag.name}> attribute "{attr_name}"',
                                'details': f'Value: {v[:120]}',
                            })

            # --- Obfuscation patterns in raw content ---
            obfuscation_patterns = [
                (r'String\.fromCharCode', 'String.fromCharCode'),
                (r'\bunescape\s*\(', 'unescape()'),
                (r'\batob\s*\(', 'atob()'),
            ]
            for pattern, desc in obfuscation_patterns:
                if re.search(pattern, content):
                    findings.append({
                        'severity': 'HIGH',
                        'category': 'Obfuscation',
                        'message': f'{desc} detected in HTML content',
                        'details': 'Commonly used to hide malicious payloads',
                    })

            tools_used.append({
                'name': 'BeautifulSoup',
                'status': 'success',
                'type': 'custom',
                'timestamp': datetime.now().isoformat(),
            })

        except Exception as exc:
            findings.append({
                'severity': 'ERROR',
                'category': 'HTML Analysis Error',
                'message': f'Error during HTML analysis: {exc}',
                'details': str(filepath),
            })
            tools_used.append({
                'name': 'BeautifulSoup',
                'status': 'error',
                'type': 'custom',
                'timestamp': datetime.now().isoformat(),
            })

        return {'findings': findings, 'tools_used': tools_used}

    # ------------------------------------------------------------------
    # LNK (shortcut) analysis
    # ------------------------------------------------------------------
    def _analyze_lnk(self, filepath: Path) -> Dict:
        """Analyze Windows .lnk shortcuts using LnkParse3."""
        findings: List[Dict] = []
        tools_used: List[Dict] = []

        if not HAS_LNKPARSE:
            tools_used.append({
                'name': 'LnkParse3',
                'status': 'unavailable',
                'type': 'custom',
                'timestamp': datetime.now().isoformat(),
            })
            findings.append({
                'severity': 'INFO',
                'category': 'Dependency Missing',
                'message': 'LnkParse3 not installed -- LNK analysis skipped',
                'details': 'Install with: pip install LnkParse3',
            })
            return {'findings': findings, 'tools_used': tools_used}

        try:
            with open(str(filepath), 'rb') as f:
                lnk = LnkParse3.lnk_file(f)

            lnk_json = lnk.get_json()
            # lnk_json is typically a dict or JSON-serialisable structure
            if isinstance(lnk_json, str):
                import json
                lnk_json = json.loads(lnk_json)

            # Extract target and arguments from various possible locations
            target = ''
            arguments = ''

            # Try data section
            data = lnk_json.get('data', {})
            if isinstance(data, dict):
                target = data.get('relative_path', '') or ''
                arguments = data.get('command_line_arguments', '') or ''

            # Try link_info
            link_info = lnk_json.get('link_info', {})
            if isinstance(link_info, dict):
                local_base = link_info.get('local_base_path', '') or ''
                if local_base:
                    target = local_base

            # Also try extra data
            extra = lnk_json.get('extra', {})
            if isinstance(extra, dict):
                env_props = extra.get('ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK', {})
                if isinstance(env_props, dict):
                    target_env = env_props.get('target_unicode', '') or env_props.get('target_ansi', '') or ''
                    if target_env:
                        target = target_env

            target_lower = target.lower()
            target_basename = Path(target).name.lower() if target else ''

            # Check for dangerous target
            if target_basename in self.LNK_DANGEROUS_TARGETS:
                findings.append({
                    'severity': 'CRITICAL',
                    'category': 'Dangerous LNK Target',
                    'message': f'Shortcut targets dangerous executable: {target_basename}',
                    'details': f'Full target path: {target}',
                })

            # Check arguments for dangerous patterns
            if arguments:
                for pattern in self.LNK_DANGEROUS_ARG_PATTERNS:
                    if re.search(pattern, arguments):
                        findings.append({
                            'severity': 'CRITICAL',
                            'category': 'Dangerous LNK Arguments',
                            'message': f'Suspicious argument pattern in shortcut: {pattern}',
                            'details': f'Arguments: {arguments[:300]}',
                        })

                # Very long arguments
                if len(arguments) > 200:
                    findings.append({
                        'severity': 'HIGH',
                        'category': 'Long LNK Arguments',
                        'message': f'Shortcut has very long arguments ({len(arguments)} chars)',
                        'details': (
                            'Long argument strings are often used to obfuscate commands. '
                            f'Preview: {arguments[:200]}...'
                        ),
                    })

            tools_used.append({
                'name': 'LnkParse3',
                'status': 'success',
                'type': 'custom',
                'timestamp': datetime.now().isoformat(),
            })

        except Exception as exc:
            findings.append({
                'severity': 'ERROR',
                'category': 'LNK Analysis Error',
                'message': f'Error during LNK analysis: {exc}',
                'details': str(filepath),
            })
            tools_used.append({
                'name': 'LnkParse3',
                'status': 'error',
                'type': 'custom',
                'timestamp': datetime.now().isoformat(),
            })

        return {'findings': findings, 'tools_used': tools_used}

    # ------------------------------------------------------------------
    # Entropy calculation
    # ------------------------------------------------------------------
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of a byte sequence."""
        if not data:
            return 0.0
        length = len(data)
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _base_result() -> Dict:
        """Return the skeleton result dict."""
        return {
            'tool_name': 'Universal Attachment Analyzer',
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'tools_used': [],
        }
