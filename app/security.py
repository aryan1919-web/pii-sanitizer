"""
Malicious file & code filtering security layer.

Scans uploaded files for threats BEFORE saving or sanitizing.
Returns (is_safe, reason) — if not safe, the upload is rejected.
"""

import io
import os
import re
import json
import struct
import zipfile
import mimetypes

# ── Config ──────────────────────────────────────────────────
MAX_FILE_SIZE = 50 * 1024 * 1024          # 50 MB
MAX_JSON_DEPTH = 50
MAX_STRING_VALUE_SIZE = 1 * 1024 * 1024   # 1 MB
MAX_IMAGE_PIXELS = 100_000_000            # 100 megapixels

ALLOWED_EXTENSIONS = {
    '.docx', '.pdf', '.xlsx', '.xls', '.doc', '.ppt', '.pptx',
    '.sql', '.csv', '.json', '.txt', '.xml',
    '.png', '.jpg', '.jpeg', '.tiff', '.tif', '.bmp',
    '.webp', '.gif', '.heic',
}

# MIME expectations per extension
_EXPECTED_MIMES = {
    '.docx': {'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'},
    '.xlsx': {'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'},
    '.xls':  {'application/vnd.ms-excel'},
    '.pptx': {'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/zip'},
    '.ppt':  {'application/vnd.ms-powerpoint'},
    '.doc':  {'application/msword'},
    '.pdf':  {'application/pdf'},
    '.sql':  {'text/plain', 'application/sql', 'text/x-sql'},
    '.csv':  {'text/plain', 'text/csv'},
    '.json': {'text/plain', 'application/json'},
    '.txt':  {'text/plain'},
    '.xml':  {'text/plain', 'text/xml', 'application/xml'},
    '.png':  {'image/png'},
    '.jpg':  {'image/jpeg'},
    '.jpeg': {'image/jpeg'},
    '.tiff': {'image/tiff'},
    '.tif':  {'image/tiff'},
    '.bmp':  {'image/bmp', 'image/x-ms-bmp'},
    '.webp': {'image/webp'},
    '.gif':  {'image/gif'},
    '.heic': {'image/heic'},
}

# Executable magic byte signatures (offset 0)
_EXE_SIGNATURES = [
    (b'MZ',              'PE/EXE executable'),
    (b'\x7fELF',         'ELF executable'),
    (b'\xfe\xed\xfa\xce', 'Mach-O executable'),
    (b'\xfe\xed\xfa\xcf', 'Mach-O 64 executable'),
    (b'\xca\xfe\xba\xbe', 'Java class / Mach-O fat'),
    (b'\xce\xfa\xed\xfe', 'Mach-O reverse'),
    (b'\xcf\xfa\xed\xfe', 'Mach-O 64 reverse'),
]


def scan_file(filename: str, file_bytes: bytes) -> tuple:
    """
    Main entry point: scans file_bytes for malicious content.
    Returns (is_safe: bool, reason: str).
    """
    ext = os.path.splitext(filename or '')[1].lower()

    # A. File type validation
    ok, reason = _check_file_type(filename, ext, file_bytes)
    if not ok:
        return False, reason

    # B. Binary / executable detection
    ok, reason = _check_executables(file_bytes)
    if not ok:
        return False, reason

    # Format-specific scans
    if ext in ('.docx', '.xlsx', '.xls', '.pptx', '.doc', '.ppt'):
        ok, reason = _scan_office(file_bytes, ext)
        if not ok:
            return False, reason

    elif ext == '.pdf':
        ok, reason = _scan_pdf(file_bytes)
        if not ok:
            return False, reason

    elif ext == '.sql':
        ok, reason = _scan_sql(file_bytes)
        if not ok:
            return False, reason

    elif ext == '.csv':
        ok, reason = _scan_csv(file_bytes)
        if not ok:
            return False, reason

    elif ext == '.json':
        ok, reason = _scan_json(file_bytes)
        if not ok:
            return False, reason

    elif ext in ('.txt', '.xml'):
        ok, reason = _scan_text(file_bytes)
        if not ok:
            return False, reason

    elif ext in ('.png', '.jpg', '.jpeg', '.tiff', '.tif', '.bmp', '.webp', '.gif', '.heic'):
        ok, reason = _scan_image(file_bytes, ext)
        if not ok:
            return False, reason

    return True, ''


# ═══════════════════════════════════════════════════════════
# A. File Type Validation
# ═══════════════════════════════════════════════════════════

def _check_file_type(filename: str, ext: str, data: bytes) -> tuple:
    # Size limit
    if len(data) > MAX_FILE_SIZE:
        return False, f'File too large ({len(data) // (1024*1024)} MB). Maximum is 50 MB'

    # Extension whitelist
    if ext not in ALLOWED_EXTENSIONS:
        return False, f'File type "{ext}" is not allowed'

    # Double extension detection
    name_no_ext = os.path.splitext(filename)[0]
    inner_ext = os.path.splitext(name_no_ext)[1].lower()
    if inner_ext in ('.exe', '.bat', '.cmd', '.com', '.msi', '.scr', '.pif',
                     '.vbs', '.js', '.ps1', '.sh', '.dll', '.sys', '.cpl',
                     '.hta', '.wsf', '.jar', '.apk'):
        return False, f'Double extension detected ("{inner_ext}{ext}")'

    # MIME type verification via magic bytes
    guessed_mime, _ = mimetypes.guess_type(filename)
    actual_mime = _detect_mime(data)
    expected = _EXPECTED_MIMES.get(ext, set())
    if actual_mime and expected and actual_mime not in expected:
        if guessed_mime and guessed_mime not in expected:
            return False, f'File type mismatch: extension is "{ext}" but content appears to be "{actual_mime}"'

    return True, ''


def _detect_mime(data: bytes) -> str:
    """Detect MIME from magic bytes."""
    if data[:4] == b'%PDF':
        return 'application/pdf'
    if data[:2] == b'MZ':
        return 'application/x-dosexec'
    if data[:4] == b'\x7fELF':
        return 'application/x-elf'
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        return 'image/png'
    if data[:3] == b'\xff\xd8\xff':
        return 'image/jpeg'
    if data[:4] in (b'\x49\x49\x2A\x00', b'\x4D\x4D\x00\x2A'):
        return 'image/tiff'
    if data[:2] == b'BM':
        return 'image/bmp'
    if data[:4] == b'RIFF' and len(data) >= 12 and data[8:12] == b'WEBP':
        return 'image/webp'
    if data[:6] in (b'GIF87a', b'GIF89a'):
        return 'image/gif'
    if len(data) >= 12 and data[4:8] == b'ftyp':
        return 'image/heic'
    if data[:4] == b'PK\x03\x04':
        return 'application/zip'  # Could be DOCX/XLSX/PPTX/ZIP
    if data[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        return 'application/vnd.ms-excel'  # OLE compound (old xls/doc/ppt)
    return ''


# ═══════════════════════════════════════════════════════════
# B. Binary / Executable Detection
# ═══════════════════════════════════════════════════════════

def _check_executables(data: bytes) -> tuple:
    for sig, desc in _EXE_SIGNATURES:
        if data[:len(sig)] == sig:
            return False, f'File is a {desc}'

    # Shebang detection
    if data[:2] == b'#!':
        first_line = data[:80].split(b'\n')[0].lower()
        if any(s in first_line for s in [b'/bin/', b'/usr/', b'python', b'perl', b'ruby', b'node']):
            return False, 'File is a script (shebang detected)'

    # Embedded PE header anywhere in file (beyond first 4 bytes)
    if b'MZ' in data[4:] and b'This program' in data:
        return False, 'Embedded executable detected inside file'

    return True, ''


# ═══════════════════════════════════════════════════════════
# C. Office Document Scanning (DOCX, XLSX)
# ═══════════════════════════════════════════════════════════

def _scan_office(data: bytes, ext: str) -> tuple:
    if ext in ('.xls', '.doc', '.ppt'):
        # Old binary OLE format — check for basic macro markers
        if b'VBA' in data and b'Macro' in data:
            return False, 'VBA macro detected in legacy Office file'
        return True, ''

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return False, 'Invalid Office document (corrupted ZIP structure)'

    names = zf.namelist()
    names_lower = [n.lower() for n in names]

    # Macro detection
    macro_markers = ['vbaproject.bin', 'vbadata.xml']
    for marker in macro_markers:
        if any(marker in n for n in names_lower):
            return False, 'VBA macro detected in Office document'

    # OLE object detection
    if any('oleobject' in n for n in names_lower):
        return False, 'Embedded OLE object detected in Office document'

    # External relationship / template injection
    rels_files = [n for n in names if n.endswith('.rels')]
    for rname in rels_files:
        try:
            rels_content = zf.read(rname).decode('utf-8', errors='ignore').lower()
            if 'targetmode="external"' in rels_content:
                if any(kw in rels_content for kw in ['attachedtemplate', 'oleobject', 'frame']):
                    return False, 'External template injection detected in Office document'
        except Exception:
            pass

    # DDE detection
    if ext == '.xlsx':
        for n in names:
            if 'sharedstrings' in n.lower() or 'sheet' in n.lower():
                try:
                    content = zf.read(n).decode('utf-8', errors='ignore').upper()
                    if any(kw in content for kw in ['=DDE(', '=CMD|', 'DDEAUTO', '=MSEXCEL|']):
                        return False, 'DDE command injection detected in spreadsheet'
                except Exception:
                    pass

    if ext == '.docx':
        for n in names:
            if 'document.xml' in n.lower():
                try:
                    content = zf.read(n).decode('utf-8', errors='ignore').upper()
                    if 'DDEAUTO' in content or ('DDE' in content and 'INSTRTEXT' in content):
                        return False, 'DDE command injection detected in document'
                except Exception:
                    pass

    zf.close()
    return True, ''


# ═══════════════════════════════════════════════════════════
# D. PDF Scanning
# ═══════════════════════════════════════════════════════════

def _scan_pdf(data: bytes) -> tuple:
    if not data[:5].startswith(b'%PDF'):
        return False, 'Invalid PDF (missing PDF header)'

    upper = data.upper()

    # JavaScript detection
    js_markers = [b'/JAVASCRIPT', b'/JS ', b'/JS(', b'/JS<']
    for marker in js_markers:
        if marker in upper:
            return False, 'JavaScript detected in PDF'

    # Auto-execution actions
    if b'/OPENACTION' in upper or b'/AA ' in upper or b'/AA>' in upper:
        if b'/JAVASCRIPT' in upper or b'/JS' in upper or b'/LAUNCH' in upper:
            return False, 'Auto-execution action with script detected in PDF'

    # Launch action
    if b'/LAUNCH' in upper:
        return False, 'Launch action detected in PDF (potential command execution)'

    # Embedded files
    if b'/EMBEDDEDFILE' in upper and b'/FILESPEC' in upper:
        return False, 'Embedded file detected in PDF'

    # Suspicious URI schemes
    uri_pattern = re.compile(rb'/URI\s*\((javascript:|data:text/html|vbscript:)', re.IGNORECASE)
    if uri_pattern.search(data):
        return False, 'Suspicious URI scheme detected in PDF'

    return True, ''


# ═══════════════════════════════════════════════════════════
# E. SQL Injection / Dangerous SQL
# ═══════════════════════════════════════════════════════════

_SQL_DESTRUCTIVE = re.compile(
    r'''(?ix)
    \b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA))
    |\b(?:TRUNCATE\s+TABLE)
    |\b(?:ALTER\s+TABLE\s+\S+\s+DROP)
    |\b(?:EXEC\s*\(|EXECUTE\s*\()
    |\bxp_cmdshell\b
    |\bsp_OACreate\b
    |\bLOAD_FILE\s*\(
    |\bINTO\s+(?:OUTFILE|DUMPFILE)\b
    |\bCOPY\s+.*\bFROM\s+PROGRAM\b
    ''')

_SQL_COMMENT_OBFUSCATION = re.compile(r'/\*!')


def _scan_sql(data: bytes) -> tuple:
    try:
        text = data.decode('utf-8', errors='ignore')
    except Exception:
        text = data.decode('latin-1', errors='ignore')

    if _SQL_DESTRUCTIVE.search(text):
        match = _SQL_DESTRUCTIVE.search(text)
        snippet = match.group(0).strip()[:60]
        return False, f'Destructive SQL statement detected: "{snippet}"'

    if _SQL_COMMENT_OBFUSCATION.search(text):
        return False, 'MySQL conditional comment obfuscation detected in SQL'

    return True, ''


# ═══════════════════════════════════════════════════════════
# F. CSV / Data Injection
# ═══════════════════════════════════════════════════════════

_CSV_FORMULA_DANGEROUS = re.compile(
    r'''(?i)
    ^[=+\-@]
    .*(?:CMD\s*[\(|]|SYSTEM\s*\(|EXEC\s*\(|HYPERLINK\s*\(
       |IMPORTXML\s*\(|IMPORTDATA\s*\(|MSEXCEL\s*\|
       |\|cmd|\|powershell|\|bash|\|calc)
    ''', re.VERBOSE)


def _scan_csv(data: bytes) -> tuple:
    try:
        text = data.decode('utf-8', errors='ignore')
    except Exception:
        text = data.decode('latin-1', errors='ignore')

    for i, line in enumerate(text.split('\n')[:2000], 1):
        for cell in line.split(','):
            cell = cell.strip().strip('"').strip("'")
            if _CSV_FORMULA_DANGEROUS.match(cell):
                snippet = cell[:80]
                return False, f'Formula injection detected in CSV (row {i}): "{snippet}"'

    return True, ''


# ═══════════════════════════════════════════════════════════
# G. JSON Security
# ═══════════════════════════════════════════════════════════

_JSON_SCRIPT_PATTERN = re.compile(
    r'<script|javascript:|onerror\s*=|onload\s*=', re.IGNORECASE)

_JSON_PROTO_KEYS = {'__proto__', 'constructor', 'prototype'}


def _scan_json(data: bytes) -> tuple:
    try:
        text = data.decode('utf-8', errors='ignore')
    except Exception:
        text = data.decode('latin-1', errors='ignore')

    # Check nesting depth before full parse
    depth = 0
    max_depth = 0
    for ch in text[:500_000]:  # Sample first 500K chars
        if ch in ('{', '['):
            depth += 1
            max_depth = max(max_depth, depth)
            if max_depth > MAX_JSON_DEPTH:
                return False, f'JSON nesting depth exceeds limit ({MAX_JSON_DEPTH})'
        elif ch in ('}', ']'):
            depth -= 1

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return True, ''  # Let the parser handle invalid JSON later

    issues = _walk_json(parsed, 0)
    if issues:
        return False, issues

    return True, ''


def _walk_json(obj, depth: int) -> str:
    if depth > MAX_JSON_DEPTH:
        return f'JSON nesting depth exceeds limit ({MAX_JSON_DEPTH})'

    if isinstance(obj, dict):
        for key, val in obj.items():
            if key in _JSON_PROTO_KEYS:
                return f'Prototype pollution key detected: "{key}"'
            if isinstance(val, str):
                if len(val) > MAX_STRING_VALUE_SIZE:
                    return f'JSON string value exceeds 1 MB'
                if _JSON_SCRIPT_PATTERN.search(val):
                    return f'Script injection detected in JSON value'
            issue = _walk_json(val, depth + 1)
            if issue:
                return issue
    elif isinstance(obj, list):
        for item in obj:
            issue = _walk_json(item, depth + 1)
            if issue:
                return issue
    elif isinstance(obj, str):
        if len(obj) > MAX_STRING_VALUE_SIZE:
            return 'JSON string value exceeds 1 MB'
        if _JSON_SCRIPT_PATTERN.search(obj):
            return 'Script injection detected in JSON value'

    return ''


# ═══════════════════════════════════════════════════════════
# H. Text File Scanning
# ═══════════════════════════════════════════════════════════

_TEXT_SCRIPT_PATTERNS = re.compile(
    r'''(?i)
    <script[\s>]
    |<\?php
    |<%[\s=@]
    |\binvoke-expression\b
    |\bIEX\s*\(
    |\bNew-Object\s+System\.Net\.WebClient\b
    ''', re.VERBOSE)

_BASE64_PE = re.compile(r'TVqQ[A-Za-z0-9+/=]{40,}|TVpQ[A-Za-z0-9+/=]{40,}')

_SUSPICIOUS_SCHEMES = re.compile(
    r'data:text/html|javascript:|vbscript:', re.IGNORECASE)


def _scan_text(data: bytes) -> tuple:
    try:
        text = data.decode('utf-8', errors='ignore')
    except Exception:
        text = data.decode('latin-1', errors='ignore')

    if _TEXT_SCRIPT_PATTERNS.search(text):
        match = _TEXT_SCRIPT_PATTERNS.search(text)
        snippet = match.group(0).strip()[:40]
        return False, f'Embedded script/code detected in text file: "{snippet}"'

    if _BASE64_PE.search(text):
        return False, 'Base64-encoded executable payload detected in text file'

    if _SUSPICIOUS_SCHEMES.search(text):
        return False, 'Suspicious URI scheme detected in text file'

    return True, ''


# ═══════════════════════════════════════════════════════════
# I. Image File Validation
# ═══════════════════════════════════════════════════════════

def _scan_image(data: bytes, ext: str) -> tuple:
    # Magic bytes verification
    if ext == '.png':
        if data[:8] != b'\x89PNG\r\n\x1a\n':
            return False, 'Invalid PNG file (bad magic bytes)'

        # PNG decompression bomb — read IHDR chunk for dimensions
        if len(data) >= 24:
            try:
                width = struct.unpack('>I', data[16:20])[0]
                height = struct.unpack('>I', data[20:24])[0]
                pixels = width * height
                if pixels > MAX_IMAGE_PIXELS:
                    return False, f'Image bomb detected: {width}x{height} = {pixels:,} pixels (max {MAX_IMAGE_PIXELS:,})'
            except struct.error:
                pass

    elif ext in ('.jpg', '.jpeg'):
        if data[:3] != b'\xff\xd8\xff':
            return False, 'Invalid JPEG file (bad magic bytes)'

    elif ext in ('.tiff', '.tif'):
        if data[:4] not in (b'\x49\x49\x2A\x00', b'\x4D\x4D\x00\x2A'):
            return False, 'Invalid TIFF file (bad magic bytes)'

    elif ext == '.bmp':
        if data[:2] != b'BM':
            return False, 'Invalid BMP file (bad magic bytes)'

    elif ext == '.webp':
        if data[:4] != b'RIFF' or len(data) < 12 or data[8:12] != b'WEBP':
            return False, 'Invalid WebP file (bad magic bytes)'

    elif ext == '.gif':
        if data[:6] not in (b'GIF87a', b'GIF89a'):
            return False, 'Invalid GIF file (bad magic bytes)'

    elif ext == '.heic':
        if len(data) >= 12 and data[4:8] != b'ftyp':
            return False, 'Invalid HEIC file (bad magic bytes)'

    # Polyglot detection — scan after image header for embedded code
    search_region = data[100:]  # Skip legitimate header
    polyglot_markers = [b'<html', b'<script', b'<?php', b'<%']
    for marker in polyglot_markers:
        if marker in search_region[:10000]:  # Check first 10KB after header
            return False, f'Polyglot file detected: image contains embedded "{marker.decode(errors="ignore")}" content'
    # MZ (PE executable) is only suspicious at the very start — random pixel data can contain 0x4D5A
    if data[:2] == b'MZ':
        return False, 'Polyglot file detected: image contains embedded "MZ" content'

    # EXIF script injection
    exif_region = data[:65536]  # EXIF is in first 64KB
    if b'<script' in exif_region.lower() or b'javascript:' in exif_region.lower():
        return False, 'Script injection detected in image metadata (EXIF)'

    return True, ''
