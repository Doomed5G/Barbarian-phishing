#!/usr/bin/env python3
"""
Barbarian Phishing
Analyzes email attachments for potential malicious content using Didier Stevens tools
"""

import os
import sys
import subprocess
import json
import hashlib
from datetime import datetime
from pathlib import Path
import re
from typing import Dict, List, Tuple

import html as _html
# Try to import custom security analysis tools
try:
    from tools.custom import (UniversalAttachmentAnalyzer, DomainIntelAnalyzer,
        ImageForensicsAnalyzer, HeaderAnalyzer, BodyLinkAnalyzer,
        PDFAnalyzer, OfficeAnalyzer, code_info, families,
        TOOL_CATALOG)
    CUSTOM_TOOLS_AVAILABLE = True
except ImportError:
    CUSTOM_TOOLS_AVAILABLE = False
    code_info = lambda c: {"title": c, "what": "", "why": "", "family": "Other"}
    families = lambda: {}
    TOOL_CATALOG = {}

_REPORT_CSS = r"""
:root {
    --bg: #0f1419;
    --panel: #182028;
    --panel-2: #1f2731;
    --border: #2a3340;
    --fg: #e6edf3;
    --fg-dim: #8b949e;
    --accent: #58a6ff;
    --crit: #f85149;
    --high: #fb8500;
    --med: #d29922;
    --low: #a5d6a7;
    --clean: #3fb950;
    --info: #58a6ff;
    --shadow: 0 2px 8px rgba(0,0,0,0.4);
}
[data-theme="light"] {
    --bg: #f5f6f8;
    --panel: #ffffff;
    --panel-2: #f1f3f5;
    --border: #d0d7de;
    --fg: #1f2328;
    --fg-dim: #57606a;
    --accent: #0969da;
    --crit: #cf222e;
    --high: #d97706;
    --med: #bf8700;
    --low: #1a7f37;
    --clean: #1a7f37;
    --info: #0969da;
    --shadow: 0 2px 8px rgba(0,0,0,0.08);
}

* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    background: var(--bg);
    color: var(--fg);
    line-height: 1.5;
    font-size: 14px;
}

/* ----- Hero ----- */
.hero {
    display: flex; align-items: center; justify-content: space-between;
    padding: 18px 28px;
    background: linear-gradient(180deg, var(--panel) 0%, var(--bg) 100%);
    border-bottom: 1px solid var(--border);
}
.hero h1 { margin: 0; font-size: 1.4rem; }
.hero-meta { color: var(--fg-dim); font-size: 0.85em; margin-top: 2px; }
.theme-toggle {
    background: var(--panel-2); color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 999px; padding: 6px 12px;
    font-size: 1.1em; cursor: pointer;
}
.theme-toggle:hover { background: var(--accent); color: #fff; }

/* ----- Tiles ----- */
.tiles {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px; padding: 16px 28px;
}
.tile {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 14px 16px;
    box-shadow: var(--shadow);
    border-left: 4px solid var(--border);
}
.tile-num { font-size: 1.6rem; font-weight: 700; }
.tile-label { color: var(--fg-dim); font-size: 0.85em; }
.tile-malicious { border-left-color: var(--crit); }
.tile-malicious .tile-num { color: var(--crit); }
.tile-suspicious { border-left-color: var(--high); }
.tile-suspicious .tile-num { color: var(--high); }
.tile-clean { border-left-color: var(--clean); }
.tile-clean .tile-num { color: var(--clean); }
.tile-noverdict { border-left-color: var(--fg-dim); }

/* ----- Toolbar ----- */
.toolbar {
    display: flex; flex-wrap: wrap; gap: 12px; align-items: center;
    padding: 12px 28px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 50;
}
.filter-pills { display: flex; gap: 6px; flex-wrap: wrap; }
.pill {
    background: var(--panel-2); color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 999px; padding: 5px 14px;
    cursor: pointer; font-size: 0.88em;
    transition: background 0.15s, color 0.15s, border-color 0.15s;
}
.pill:hover { border-color: var(--accent); }
.pill.active { background: var(--accent); color: #fff; border-color: var(--accent); }
.pill[data-filter="malicious"].active { background: var(--crit); border-color: var(--crit); }
.pill[data-filter="suspicious"].active { background: var(--high); border-color: var(--high); color: #000; }
.pill[data-filter="clean"].active { background: var(--clean); border-color: var(--clean); }

.search-box {
    flex: 1; min-width: 220px;
    background: var(--panel-2); color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 8px; padding: 7px 12px;
    font-size: 0.9em;
}
.search-box::placeholder { color: var(--fg-dim); }
.search-box:focus { outline: 2px solid var(--accent); outline-offset: -1px; }

.bulk-actions { color: var(--fg-dim); font-size: 0.85em; }
.link-btn {
    background: none; border: none; color: var(--accent);
    cursor: pointer; padding: 0 4px; font-size: 0.9em;
}
.link-btn:hover { text-decoration: underline; }
.sep { padding: 0 4px; }

/* ----- Container ----- */
.container { max-width: 1300px; margin: 16px auto; padding: 0 28px; }

/* ----- Email blocks ----- */
.email {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; margin-bottom: 18px; padding: 16px 18px;
    box-shadow: var(--shadow);
}
.email-head { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }
.email-head h2 { margin: 0; font-size: 1.1rem; }
.email-chips { display: flex; gap: 6px; }
.chip {
    border-radius: 999px; padding: 2px 10px;
    font-size: 0.78em; font-weight: 600;
}
.chip-crit { background: var(--crit); color: #fff; }
.chip-high { background: var(--high); color: #000; }
.chip-med  { background: var(--med);  color: #000; }
.chip-clean{ background: var(--clean);color: #fff; }
.email-link {
    background: var(--panel-2); border-left: 3px solid var(--accent);
    border-radius: 6px; padding: 8px 12px; margin: 10px 0;
    word-break: break-all; font-size: 0.92em;
}
.email-link a { color: var(--accent); text-decoration: none; }
.email-link a:hover { text-decoration: underline; }
.muted { color: var(--fg-dim); }

/* ----- Attachment rows ----- */
.rows { margin-top: 10px; }
.row {
    background: var(--panel-2); border: 1px solid var(--border);
    border-radius: 8px; margin: 6px 0;
    transition: border-color 0.15s;
}
.row[open] { border-color: var(--accent); }
.row-summary {
    list-style: none;
    cursor: pointer;
    display: flex; align-items: center; gap: 12px;
    padding: 10px 14px;
    user-select: none;
}
.row-summary::-webkit-details-marker { display: none; }
.row-summary::before {
    content: "▶";
    color: var(--fg-dim);
    font-size: 0.7em;
    width: 12px;
    transition: transform 0.15s;
}
.row[open] > .row-summary::before { transform: rotate(90deg); }
.dot {
    width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0;
    background: var(--fg-dim);
}
.dot-malicious { background: var(--crit); box-shadow: 0 0 8px var(--crit); }
.dot-suspicious { background: var(--high); box-shadow: 0 0 8px var(--high); }
.dot-medium { background: var(--med); }
.dot-clean { background: var(--clean); }
.dot-noverdict { background: var(--fg-dim); }
.row-name {
    font-weight: 600; flex-shrink: 0; max-width: 320px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.type-pill {
    background: var(--bg); border: 1px solid var(--border);
    border-radius: 999px; padding: 1px 8px;
    font-size: 0.75em; color: var(--fg-dim); flex-shrink: 0;
}
.row-headline {
    flex: 1; min-width: 0;
    color: var(--fg-dim); font-size: 0.9em;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.verdict-chip {
    border-radius: 6px; padding: 3px 10px;
    font-size: 0.72em; font-weight: 700; letter-spacing: 0.04em;
    flex-shrink: 0;
}
.verdict-malicious { background: var(--crit); color: #fff; }
.verdict-suspicious { background: var(--high); color: #000; }
.verdict-clean { background: var(--clean); color: #fff; }
.verdict-noverdict { background: var(--panel); color: var(--fg-dim); border: 1px solid var(--border); }
.score-pill {
    background: var(--panel); color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 999px; padding: 1px 9px;
    font-size: 0.78em; font-family: ui-monospace, monospace;
    flex-shrink: 0;
}
.row-body {
    padding: 0 14px 14px 14px;
    border-top: 1px solid var(--border);
    margin-top: 2px; padding-top: 12px;
}

/* ----- Findings ----- */
.findings { display: flex; flex-direction: column; gap: 8px; }
.finding {
    background: var(--bg); border: 1px solid var(--border);
    border-left-width: 3px;
    border-radius: 6px; padding: 9px 12px;
}
.finding.sev-CRITICAL, .finding.sev-ERROR { border-left-color: var(--crit); }
.finding.sev-HIGH                          { border-left-color: var(--high); }
.finding.sev-MEDIUM, .finding.sev-WARNING  { border-left-color: var(--med); }
.finding.sev-LOW                           { border-left-color: var(--low); }
.finding.sev-INFO                          { border-left-color: var(--info); }
.finding-row {
    display: flex; align-items: center; flex-wrap: wrap; gap: 8px;
    margin-bottom: 4px;
}
.sev-chip {
    border-radius: 4px; padding: 1px 8px;
    font-size: 0.72em; font-weight: 700; letter-spacing: 0.04em;
}
.sev-chip-CRITICAL, .sev-chip-ERROR { background: var(--crit); color: #fff; }
.sev-chip-HIGH                       { background: var(--high); color: #000; }
.sev-chip-MEDIUM, .sev-chip-WARNING  { background: var(--med); color: #000; }
.sev-chip-LOW                        { background: var(--low); color: #000; }
.sev-chip-INFO                       { background: var(--info); color: #fff; }
.finding-title { font-weight: 600; }
.code-tag {
    background: var(--panel); color: var(--fg-dim);
    border: 1px solid var(--border);
    border-radius: 4px; padding: 1px 6px;
    font-size: 0.78em; font-family: ui-monospace, monospace;
    margin-left: auto;
}
.finding-msg { color: var(--fg); font-size: 0.92em; }
.finding-more {
    margin-top: 6px;
    font-size: 0.9em;
}
.finding-more summary {
    cursor: pointer; color: var(--accent);
    font-size: 0.85em;
}
.finding-more summary:hover { text-decoration: underline; }
.finding-more p { margin: 6px 0; }
.finding-more pre {
    background: var(--panel-2); padding: 8px;
    border-radius: 4px; overflow-x: auto;
    font-size: 0.82em; max-height: 240px;
}
.finding-evidence { font-family: ui-monospace, monospace; font-size: 0.82em;
                    background: var(--panel-2); padding: 6px 8px;
                    border-radius: 4px; margin-top: 4px; word-break: break-all; }
.finding-ioc { font-size: 0.85em; word-break: break-all; }
.finding-attck { font-size: 0.85em; color: var(--fg-dim); margin-top: 4px; }
.finding-attck code { color: var(--accent); }

/* ----- IOC + sub-details + tools ----- */
details.ioc-section, details.subdetails, details.subsection {
    background: var(--panel-2); border: 1px solid var(--border);
    border-radius: 6px; padding: 6px 12px;
    margin: 8px 0;
}
details.subsection { background: var(--panel); padding: 8px 14px; }
details summary {
    cursor: pointer; font-weight: 600; padding: 4px 0;
    list-style: none;
}
details summary::-webkit-details-marker { display: none; }
details summary::before {
    content: "▶"; color: var(--fg-dim); font-size: 0.7em;
    margin-right: 8px; display: inline-block;
    transition: transform 0.15s;
}
details[open] > summary::before { transform: rotate(90deg); }

.ioc-table { width: 100%; border-collapse: collapse;
             font-family: ui-monospace, monospace; font-size: 0.82em;
             margin-top: 6px; }
.ioc-table th { text-align: left; padding: 6px 10px;
                background: var(--panel); color: var(--fg-dim);
                border-bottom: 1px solid var(--border); }
.ioc-table td { padding: 5px 10px; border-bottom: 1px solid var(--border);
                word-break: break-all; }

.recommendations {
    background: var(--panel-2); border-left: 3px solid var(--high);
    padding: 8px 12px; border-radius: 0 6px 6px 0;
    margin: 8px 0; font-size: 0.92em;
}
.recommendations ul { margin: 4px 0 0 18px; padding: 0; }

.hash { font-family: ui-monospace, monospace; font-size: 0.78em;
        color: var(--fg-dim); word-break: break-all; }
.hash > div { padding: 2px 0; }

.tool-pills { display: flex; flex-wrap: wrap; gap: 6px; padding: 4px 0; }
.tool-pill {
    border-radius: 999px; padding: 2px 10px;
    font-size: 0.78em; cursor: help;
    border: 1px solid var(--border);
}
.tool-success    { background: rgba(63,185,80,0.15); color: var(--clean); border-color: var(--clean); }
.tool-error      { background: rgba(248,81,73,0.15); color: var(--crit);  border-color: var(--crit); }
.tool-unavailable{ background: var(--panel-2); color: var(--fg-dim); }
.tool-fallback   { background: rgba(210,153,34,0.15); color: var(--med);  border-color: var(--med); }

.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
              gap: 4px 12px; padding-top: 4px; }
.stat-row { display: flex; justify-content: space-between; gap: 8px; font-size: 0.86em; }
.stat-key { color: var(--fg-dim); }
.stat-val { font-family: ui-monospace, monospace; }

/* ----- Sub-section cards (header / body / domain) ----- */
.header-card, .body-link-card, .domain-card {
    background: var(--panel-2); border: 1px solid var(--border);
    border-radius: 6px; padding: 12px;
}
.header-card h4, .body-link-card h4, .domain-card h4 {
    margin: 0 0 10px 0; color: var(--accent);
    border-bottom: 1px solid var(--border); padding-bottom: 6px;
}
.header-table, .link-table {
    width: 100%; border-collapse: collapse; font-size: 0.88em;
}
.header-table th, .link-table th {
    text-align: left; padding: 6px 10px;
    background: var(--panel); color: var(--fg-dim);
    border-bottom: 1px solid var(--border);
}
.header-table td, .link-table td {
    padding: 6px 10px; border-bottom: 1px solid var(--border);
    word-break: break-all;
}
.auth-badges { display: flex; gap: 6px; flex-wrap: wrap; margin: 8px 0; }
.auth-badge {
    border-radius: 999px; padding: 2px 10px;
    font-size: 0.78em; font-weight: 600;
}
.auth-badge.pass { background: rgba(63,185,80,0.15); color: var(--clean); }
.auth-badge.fail { background: rgba(248,81,73,0.15); color: var(--crit); }
.auth-badge.none { background: var(--panel); color: var(--fg-dim); }
.domain-entry {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 5px; padding: 8px; margin: 6px 0;
}
.domain-name { font-weight: 600; color: var(--clean); margin-bottom: 4px; }
.domain-detail { display: flex; gap: 6px; padding: 2px 0; font-size: 0.86em; }
.domain-detail .label { color: var(--fg-dim); min-width: 90px; }
.mismatch-yes { background: rgba(248,81,73,0.2); color: var(--crit); font-weight: 600; }
.mismatch-no  { background: rgba(63,185,80,0.15); color: var(--clean); }

/* ----- Legend ----- */
.legend {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 14px 18px; margin-top: 24px;
    box-shadow: var(--shadow);
}
.legend > details > summary {
    font-size: 1.05em; font-weight: 700; color: var(--accent);
}
.legend-body { padding-top: 10px; }
.legend-tools { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                gap: 12px; margin: 10px 0; }
.legend-tool {
    background: var(--panel-2); border: 1px solid var(--border);
    border-radius: 6px; padding: 10px 12px; font-size: 0.9em;
}
.legend-tool-head code {
    background: var(--bg); border: 1px solid var(--border);
    border-radius: 4px; padding: 1px 6px; color: var(--accent);
    font-size: 0.9em; margin-right: 6px;
}
.legend-tool-title { font-weight: 600; }
.legend-tool p { margin: 6px 0; }

.legend-family { margin: 8px 0; }
.legend-table { width: 100%; border-collapse: collapse;
                font-size: 0.85em; margin-top: 6px; }
.legend-table th { text-align: left; padding: 6px 10px;
                   background: var(--panel-2); color: var(--fg-dim);
                   border-bottom: 1px solid var(--border); }
.legend-table td { padding: 6px 10px; border-bottom: 1px solid var(--border);
                   vertical-align: top; }
.legend-table code {
    background: var(--bg); border: 1px solid var(--border);
    border-radius: 4px; padding: 1px 6px; color: var(--accent);
    font-size: 0.88em; white-space: nowrap;
}

/* ----- Filter visibility ----- */
body.filter-malicious .row:not([data-verdict="malicious"]) { display: none; }
body.filter-suspicious .row:not([data-verdict="suspicious"]) { display: none; }
body.filter-clean .row:not([data-verdict="clean"]) { display: none; }
body.filter-noverdict .row:not([data-verdict="noverdict"]) { display: none; }
.row.search-hidden { display: none; }
"""

_REPORT_JS = r"""
(function() {
    // ----- Theme toggle -----
    const root = document.documentElement;
    const toggle = document.getElementById('themeToggle');
    const stored = localStorage.getItem('barbarian-theme');
    if (stored) root.setAttribute('data-theme', stored);
    function refreshIcon() {
        const t = root.getAttribute('data-theme');
        toggle.textContent = (t === 'light') ? '☀' : '🌙';
    }
    refreshIcon();
    toggle.addEventListener('click', () => {
        const next = (root.getAttribute('data-theme') === 'light') ? 'dark' : 'light';
        root.setAttribute('data-theme', next);
        localStorage.setItem('barbarian-theme', next);
        refreshIcon();
    });

    // ----- Filter pills -----
    const pills = document.querySelectorAll('.pill');
    pills.forEach(p => {
        p.addEventListener('click', () => {
            pills.forEach(x => x.classList.remove('active'));
            p.classList.add('active');
            const f = p.dataset.filter;
            document.body.classList.remove(
                'filter-malicious', 'filter-suspicious',
                'filter-clean', 'filter-noverdict'
            );
            if (f !== 'all') document.body.classList.add('filter-' + f);
        });
    });

    // ----- Search -----
    const search = document.getElementById('searchBox');
    if (search) {
        search.addEventListener('input', () => {
            const q = search.value.trim().toLowerCase();
            document.querySelectorAll('.row').forEach(row => {
                if (!q) { row.classList.remove('search-hidden'); return; }
                const blob = (row.dataset.search || '').toLowerCase();
                if (blob.indexOf(q) === -1) row.classList.add('search-hidden');
                else row.classList.remove('search-hidden');
            });
        });
    }

    // ----- Bulk expand/collapse -----
    document.getElementById('expandAll')?.addEventListener('click', () => {
        document.querySelectorAll('.row').forEach(r => r.open = true);
    });
    document.getElementById('collapseAll')?.addEventListener('click', () => {
        document.querySelectorAll('.row').forEach(r => r.open = false);
        document.querySelectorAll('details.subsection,details.subdetails,details.ioc-section,details.finding-more')
                .forEach(d => d.open = false);
    });

    // ----- Anchor jump auto-expand -----
    if (location.hash) {
        const target = document.querySelector(location.hash);
        if (target && target.tagName === 'DETAILS') {
            target.open = true;
            target.scrollIntoView({behavior: 'smooth', block: 'start'});
        }
    }
})();
"""

class AttachmentAnalyzer:
    def __init__(self, root_folder: str, mode: str = 'normal'):
        self.root_folder = Path(root_folder)
        self.script_dir = Path(__file__).resolve().parent
        self.mode = mode  # 'normal' or 'eml'
        self.report = []
        self.suspicious_findings = []

        # Initialize custom tools if available
        if CUSTOM_TOOLS_AVAILABLE:
            self.attachment_tool = UniversalAttachmentAnalyzer()
            self.domain_tool = DomainIntelAnalyzer()
            self.image_forensics_tool = ImageForensicsAnalyzer()
            self.header_tool = HeaderAnalyzer()
            self.body_link_tool = BodyLinkAnalyzer()
            self.pdf_analyzer = PDFAnalyzer()
            self.office_analyzer = OfficeAnalyzer()
        else:
            self.attachment_tool = None
            self.domain_tool = None
            self.image_forensics_tool = None
            self.header_tool = None
            self.body_link_tool = None
            self.pdf_analyzer = None
            self.office_analyzer = None

    def calculate_hash(self, filepath: Path) -> Dict[str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes of a file"""
        hashes = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}

        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    for h in hashes.values():
                        h.update(chunk)

            return {name: h.hexdigest() for name, h in hashes.items()}
        except Exception as e:
            return {'error': str(e)}

    def run_command(self, cmd: List[str]) -> Tuple[str, str, int]:
        """Execute a command and return stdout, stderr, and return code"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timeout", -1
        except Exception as e:
            return "", str(e), -1

    def analyze_pdf(self, filepath: Path, email_body: str = "") -> Dict:
        """Analyze a PDF via the native pikepdf-based PDFAnalyzer."""
        if self.pdf_analyzer is None:
            return self._unsupported_file(filepath, '.pdf')
        result = self.pdf_analyzer.analyze(filepath, email_body=email_body)
        result['hashes'] = self.calculate_hash(filepath)
        return result

    def analyze_ole(self, filepath: Path, email_body: str = "") -> Dict:
        """Analyze an Office / OLE / RTF document via the native OfficeAnalyzer."""
        if self.office_analyzer is None:
            return self._unsupported_file(filepath, filepath.suffix.lower())
        result = self.office_analyzer.analyze(filepath, email_body=email_body)
        result['hashes'] = self.calculate_hash(filepath)
        return result

    def analyze_image(self, filepath: Path) -> Dict:
        """Analyze image files for steganography and tampering"""
        analysis = {
            'file': str(filepath),
            'type': 'Image',
            'timestamp': datetime.now().isoformat(),
            'hashes': self.calculate_hash(filepath),
            'findings': [],
            'tools_used': []
        }

        try:
            # Check for exiftool
            exiftool = self.find_tool('exiftool') or self.find_tool('exiftool.exe')
            if exiftool:
                stdout, _, code = self.run_command([
                    exiftool, str(filepath)
                ])

                if stdout and code == 0:
                    analysis['exif_data'] = stdout
                    analysis['tools_used'].append({
                        'name': 'exiftool',
                        'status': 'success',
                        'type': 'primary',
                        'timestamp': datetime.now().isoformat()
                    })

                    # Look for suspicious metadata
                    suspicious_patterns = [
                        'script', 'javascript', 'executable', 'payload',
                        'powershell', 'cmd.exe', 'eval'
                    ]

                    lower_exif = stdout.lower()
                    for pattern in suspicious_patterns:
                        if pattern in lower_exif:
                            analysis['findings'].append({
                                'severity': 'MEDIUM',
                                'category': 'Suspicious Metadata',
                                'message': f'Suspicious pattern "{pattern}" found in image metadata',
                                'details': stdout[:300]
                            })
                else:
                    analysis['tools_used'].append({
                        'name': 'exiftool',
                        'status': 'error',
                        'type': 'primary',
                        'timestamp': datetime.now().isoformat()
                    })
            else:
                analysis['tools_used'].append({
                    'name': 'exiftool',
                    'status': 'unavailable',
                    'type': 'primary',
                    'timestamp': datetime.now().isoformat()
                })

            # Check file size vs expected size (simple polyglot detection)
            file_size = filepath.stat().st_size

            # Try to read with PIL/Pillow if available
            try:
                from PIL import Image
                img = Image.open(filepath)

                analysis['tools_used'].append({
                    'name': 'PIL/Pillow',
                    'status': 'success',
                    'type': 'primary',
                    'timestamp': datetime.now().isoformat()
                })

                analysis['image_info'] = {
                    'format': img.format,
                    'mode': img.mode,
                    'size': img.size,
                    'file_size': file_size
                }

                # Simple check: if file is much larger than expected, might contain hidden data
                expected_size = img.size[0] * img.size[1] * len(img.mode)
                if file_size > expected_size * 2:
                    analysis['findings'].append({
                        'severity': 'MEDIUM',
                        'category': 'Size Anomaly',
                        'message': 'Image file size is significantly larger than expected',
                        'details': f'File size: {file_size}, Expected ~{expected_size}'
                    })

                img.close()
            except ImportError:
                analysis['tools_used'].append({
                    'name': 'PIL/Pillow',
                    'status': 'unavailable',
                    'type': 'primary',
                    'timestamp': datetime.now().isoformat()
                })
                analysis['findings'].append({
                    'severity': 'INFO',
                    'message': 'PIL/Pillow not available for deep image analysis'
                })
            except Exception as e:
                analysis['findings'].append({
                    'severity': 'MEDIUM',
                    'category': 'Image Parsing Error',
                    'message': f'Could not parse image properly: {str(e)}'
                })

            # Check for trailing data after image end
            with open(filepath, 'rb') as f:
                content = f.read()

                # Look for common file signatures in trailing data
                signatures = {
                    b'PK\x03\x04': 'ZIP/Office',
                    b'%PDF': 'PDF',
                    b'MZ': 'EXE',
                    b'\x50\x4B\x03\x04': 'ZIP'
                }

                for sig, filetype in signatures.items():
                    # Skip the first 100 bytes (image header area)
                    pos = content.find(sig, 100)
                    if pos > 0:
                        analysis['findings'].append({
                            'severity': 'HIGH',
                            'category': 'Embedded File',
                            'message': f'Possible {filetype} file embedded in image at offset {pos}',
                            'details': 'Polyglot file detected'
                        })

        except Exception as e:
            analysis['findings'].append({
                'severity': 'ERROR',
                'message': f'Error analyzing image: {str(e)}'
            })

        return analysis

    def find_tool(self, tool_name: str) -> str:
        """Find analysis tool in common locations"""
        # Check current directory
        if Path(tool_name).exists():
            return tool_name

        # Check common installation paths
        common_paths = [
            self.script_dir / 'tools' / tool_name,  # Check script's tools directory FIRST
            Path.home() / 'tools' / tool_name,
            Path('/usr/local/bin') / tool_name,
            Path('/opt/didier-stevens') / tool_name,
            Path.cwd() / tool_name,
            Path.cwd() / 'tools' / tool_name
        ]

        # Add Windows-specific paths for exiftool
        if os.name == 'nt' and 'exiftool' in tool_name.lower():
            windows_paths = [
                Path.home() / 'AppData' / 'Local' / 'Programs' / 'ExifTool' / 'ExifTool.exe',  # WinGet install location
                Path('C:/Program Files/ExifTool') / tool_name,
                Path('C:/Program Files (x86)/ExifTool') / tool_name,
                Path.home() / 'AppData' / 'Local' / 'ExifTool' / tool_name,
                self.script_dir / 'tools' / 'exiftool.exe',
                self.script_dir / 'tools' / 'exiftool(-k).exe',
            ]
            common_paths.extend(windows_paths)

        for path in common_paths:
            if path.exists():
                return str(path)

        # Try to find in PATH
        try:
            result = subprocess.run(
                ['which', tool_name] if os.name != 'nt' else ['where', tool_name],
                capture_output=True,
                text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().split('\n')[0]
        except:
            pass

        return None

    def analyze_file(self, filepath: Path) -> Dict:
        """Analyze a single file based on its type"""
        ext = filepath.suffix.lower()

        # Skip headers.txt - it's email headers, not an attachment
        if filepath.name.lower() == 'headers.txt':
            return None

        # Run magic byte validation on every file (custom tool)
        magic_findings = []
        if self.attachment_tool:
            magic_result = self.attachment_tool.validate_file_type(filepath)
            if magic_result:
                magic_findings = magic_result.get('findings', [])

        # Route to appropriate analyzer based on extension
        if ext == '.pdf':
            analysis = self.analyze_pdf(filepath)
        elif ext in ['.doc', '.xls', '.ppt', '.docx', '.xlsx', '.pptx',
                     '.docm', '.xlsm', '.pptm', '.rtf', '.msg']:
            analysis = self.analyze_ole(filepath)
        elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp']:
            analysis = self.analyze_image(filepath)
            # Run image forensics (ELA, steganography, thumbnail comparison)
            if self.image_forensics_tool:
                forensics_result = self.image_forensics_tool.analyze(filepath)
                if forensics_result:
                    analysis['findings'].extend(forensics_result.get('findings', []))
                    analysis.setdefault('tools_used', []).extend(forensics_result.get('tools_used', []))
        elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.tar.gz']:
            # Archive analysis (custom tool)
            if self.attachment_tool:
                analysis = self._wrap_custom_analysis(filepath, 'Archive', self.attachment_tool.analyze(filepath))
            else:
                analysis = self._unsupported_file(filepath, ext)
        elif ext in ['.js', '.vbs', '.ps1', '.bat', '.cmd', '.wsf', '.hta']:
            # Script analysis (custom tool)
            if self.attachment_tool:
                analysis = self._wrap_custom_analysis(filepath, 'Script', self.attachment_tool.analyze(filepath))
            else:
                analysis = self._unsupported_file(filepath, ext)
        elif ext in ['.exe', '.dll', '.scr']:
            # Executable analysis (custom tool)
            if self.attachment_tool:
                analysis = self._wrap_custom_analysis(filepath, 'Executable', self.attachment_tool.analyze(filepath))
            else:
                analysis = self._unsupported_file(filepath, ext)
        elif ext in ['.html', '.htm']:
            # HTML file analysis (custom tool)
            if self.attachment_tool:
                analysis = self._wrap_custom_analysis(filepath, 'HTML File', self.attachment_tool.analyze(filepath))
            else:
                analysis = self._unsupported_file(filepath, ext)
        elif ext == '.lnk':
            # Windows shortcut analysis (custom tool)
            if self.attachment_tool:
                analysis = self._wrap_custom_analysis(filepath, 'Windows Shortcut', self.attachment_tool.analyze(filepath))
            else:
                analysis = self._unsupported_file(filepath, ext)
        else:
            # Unknown type - still run custom tool if available
            if self.attachment_tool:
                analysis = self._wrap_custom_analysis(filepath, 'Unknown', self.attachment_tool.analyze(filepath))
            else:
                analysis = self._unsupported_file(filepath, ext)

        # Merge magic byte validation findings into analysis
        if magic_findings:
            analysis.setdefault('findings', []).extend(magic_findings)

        return analysis

    def _wrap_custom_analysis(self, filepath: Path, file_type: str, custom_result: Dict) -> Dict:
        """Wrap custom tool results into the standard analysis format"""
        analysis = {
            'file': str(filepath),
            'type': file_type,
            'timestamp': datetime.now().isoformat(),
            'hashes': self.calculate_hash(filepath),
            'findings': custom_result.get('findings', []),
            'tools_used': custom_result.get('tools_used', [])
        }
        return analysis

    def _unsupported_file(self, filepath: Path, ext: str) -> Dict:
        """Return default analysis for unsupported file types"""
        return {
            'file': str(filepath),
            'type': 'Unknown',
            'timestamp': datetime.now().isoformat(),
            'hashes': self.calculate_hash(filepath),
            'findings': [{
                'severity': 'INFO',
                'message': f'Unsupported file type: {ext}'
            }]
        }

    def analyze_email_folder(self, email_folder: Path) -> Dict:
        """Analyze all attachments in an email folder"""
        email_report = {
            'email_folder': email_folder.name,
            'timestamp': datetime.now().isoformat(),
            'attachments': [],
            'summary': {
                'total_files': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'clean': 0
            }
        }

        eml_msg = None
        eml_body = None
        eml_attachments_dir = None

        if self.mode == 'eml':
            # EML mode - parse .eml file to extract everything
            eml_file = self._find_eml_file(email_folder)
            if eml_file:
                eml_msg, eml_body, eml_attachments_dir = self._parse_eml(eml_file, email_folder)
                if not eml_msg:
                    email_report['note'] = 'Failed to parse .eml file'
                    return email_report
            else:
                email_report['note'] = 'No .eml file found in folder'
                return email_report

        # Read link.txt if it exists and extract URLs (normal mode)
        link_file = email_folder / 'link.txt'
        if link_file.exists():
            try:
                raw_text = link_file.read_text(encoding='utf-8').strip()
            except Exception:
                raw_text = link_file.read_text().strip()
            if raw_text:
                urls = re.findall(r'https?://[^\s<>"\']+', raw_text)
                email_report['links'] = urls if urls else []

        # Determine which directory contains the attachments
        if self.mode == 'eml' and eml_attachments_dir:
            attached_files_dir = eml_attachments_dir
        else:
            attached_files_dir = email_folder / 'attached_files'

        if not attached_files_dir.exists():
            email_report['note'] = 'No attached_files folder found'
        else:
            # Analyze each attachment
            for filepath in attached_files_dir.iterdir():
                if filepath.is_file():
                    analysis = self.analyze_file(filepath)
                    if analysis is None:
                        continue  # Skip headers.txt etc.

                    email_report['summary']['total_files'] += 1
                    email_report['attachments'].append(analysis)

                    # Update severity counts - count per FILE not per FINDING
                    file_max_severity = 'INFO'
                    has_warning = False
                    for finding in analysis.get('findings', []):
                        sev = finding.get('severity', 'INFO')
                        if sev == 'CRITICAL':
                            file_max_severity = 'CRITICAL'
                        elif sev == 'HIGH' and file_max_severity not in ['CRITICAL']:
                            file_max_severity = 'HIGH'
                        elif sev == 'MEDIUM' and file_max_severity not in ['CRITICAL', 'HIGH']:
                            file_max_severity = 'MEDIUM'
                        elif sev == 'WARNING':
                            has_warning = True

                    # Count this file once based on its highest severity
                    if file_max_severity == 'CRITICAL':
                        email_report['summary']['critical'] += 1
                    elif file_max_severity == 'HIGH':
                        email_report['summary']['high'] += 1
                    elif file_max_severity == 'MEDIUM':
                        email_report['summary']['medium'] += 1
                    elif file_max_severity == 'INFO' and not has_warning:
                        email_report['summary']['clean'] += 1

        # --- Custom tool analysis ---

        # Header Analysis
        if self.header_tool:
            try:
                if self.mode == 'eml' and eml_msg:
                    header_result = self.header_tool.analyze(email_folder, mode='eml', eml_msg=eml_msg)
                else:
                    header_result = self.header_tool.analyze(email_folder, mode='normal')
                email_report['header_analysis'] = header_result
            except Exception as e:
                email_report['header_analysis'] = {
                    'findings': [{'severity': 'ERROR', 'message': f'Header analysis failed: {str(e)}'}],
                    'tools_used': [{'name': 'HeaderAnalyzer', 'status': 'error'}]
                }

        # Body Link Analysis
        if self.body_link_tool:
            try:
                if self.mode == 'eml' and eml_body:
                    body_result = self.body_link_tool.analyze(email_folder, mode='eml', eml_body=eml_body)
                else:
                    body_result = self.body_link_tool.analyze(email_folder, mode='normal')
                email_report['body_link_analysis'] = body_result
            except Exception as e:
                email_report['body_link_analysis'] = {
                    'findings': [{'severity': 'ERROR', 'message': f'Body link analysis failed: {str(e)}'}],
                    'tools_used': [{'name': 'BodyLinkAnalyzer', 'status': 'error'}]
                }

        # Domain Intelligence - analyze URLs from link.txt
        if self.domain_tool and email_report.get('links'):
            try:
                domain_result = self.domain_tool.analyze(email_report['links'])
                email_report['domain_intelligence'] = domain_result
            except Exception as e:
                email_report['domain_intelligence'] = {
                    'findings': [{'severity': 'ERROR', 'message': f'Domain intelligence failed: {str(e)}'}],
                    'tools_used': [{'name': 'DomainIntelAnalyzer', 'status': 'error'}]
                }

        return email_report

    def _find_eml_file(self, email_folder: Path) -> Path:
        """Find the first .eml file in the email folder"""
        for f in email_folder.iterdir():
            if f.suffix.lower() == '.eml' and f.is_file():
                return f
        return None

    def _parse_eml(self, eml_file: Path, email_folder: Path):
        """Parse an .eml file and extract headers, body, and attachments"""
        import email
        from email import policy
        from email.parser import BytesParser

        try:
            with open(eml_file, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
        except Exception as e:
            print(f"  Error parsing .eml file: {e}")
            return None, None, None

        # Extract body (HTML preferred, then plain text)
        body = None
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/html':
                    body = part.get_content()
                    break
                elif content_type == 'text/plain' and body is None:
                    body = part.get_content()
        else:
            body = msg.get_content()

        # Extract attachments to a temp directory inside the email folder
        attachments_dir = email_folder / 'attached_files'
        attachments_dir.mkdir(exist_ok=True)

        if msg.is_multipart():
            for part in msg.iter_attachments():
                filename = part.get_filename()
                if filename:
                    attachment_path = attachments_dir / filename
                    with open(attachment_path, 'wb') as f:
                        f.write(part.get_content())

        # Also extract URLs from body for domain intel
        if body:
            urls = re.findall(r'https?://[^\s<>"\']+', body)
            # Write a temporary link.txt for domain analysis
            link_file = email_folder / 'link.txt'
            if not link_file.exists() and urls:
                link_file.write_text('\n'.join(urls), encoding='utf-8')

        return msg, body, attachments_dir

    def generate_html_report(self, all_reports: List[Dict], output_file: Path):
        """Generate the interactive HTML report.

        Layout: triage dashboard first; everything beyond the at-a-glance
        rows is collapsed by default. Embedded JS handles theme toggle,
        filter pills, search, and expand/collapse. Single self-contained
        HTML file no external assets.
        """
        rows = self._collect_attachment_rows(all_reports)
        totals = self._totals_from_rows(rows)

        css = _REPORT_CSS
        js = _REPORT_JS

        head = (
            '<!DOCTYPE html><html lang="en" data-theme="dark">'
            '<head><meta charset="UTF-8">'
            '<title>Barbarian Phishing Report</title>'
            f'<style>{css}</style></head><body>'
        )

        # ---------- HERO ----------
        gen_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        hero = (
            '<header class="hero">'
            '<div class="hero-left">'
            '<h1>🎣 Barbarian Phishing</h1>'
            f'<div class="hero-meta">{len(all_reports)} email(s) · '
            f'{totals["total"]} attachment(s) · generated {gen_at}</div>'
            '</div>'
            '<div class="hero-right">'
            f'<button class="theme-toggle" id="themeToggle" '
            f'title="Toggle theme">🌙</button>'
            '</div>'
            '</header>'
        )

        # ---------- VERDICT TILES ----------
        tiles = (
            '<section class="tiles">'
            f'<div class="tile tile-malicious"><div class="tile-num">{totals["malicious"]}</div>'
            f'<div class="tile-label">Malicious</div></div>'
            f'<div class="tile tile-suspicious"><div class="tile-num">{totals["suspicious"]}</div>'
            f'<div class="tile-label">Suspicious</div></div>'
            f'<div class="tile tile-clean"><div class="tile-num">{totals["clean"]}</div>'
            f'<div class="tile-label">Clean</div></div>'
            f'<div class="tile tile-noverdict"><div class="tile-num">{totals["other"]}</div>'
            f'<div class="tile-label">No verdict</div></div>'
            '</section>'
        )

        # ---------- TOOLBAR ----------
        toolbar = (
            '<div class="toolbar">'
            '<div class="filter-pills" role="tablist" aria-label="Filter by verdict">'
            '<button class="pill active" data-filter="all">All</button>'
            '<button class="pill" data-filter="malicious">Malicious</button>'
            '<button class="pill" data-filter="suspicious">Suspicious</button>'
            '<button class="pill" data-filter="clean">Clean</button>'
            '<button class="pill" data-filter="noverdict">No verdict</button>'
            '</div>'
            '<input type="search" id="searchBox" class="search-box" '
            'placeholder="Filter by filename, code, or message…" />'
            '<div class="bulk-actions">'
            '<button class="link-btn" id="expandAll">Expand all</button>'
            '<span class="sep">·</span>'
            '<button class="link-btn" id="collapseAll">Collapse all</button>'
            '</div>'
            '</div>'
        )

        # ---------- TRIAGE: per-email sections with attachment rows ----------
        body_main = '<main class="container">'
        for email_report in all_reports:
            body_main += self._render_email_block(email_report)

        # ---------- LEGEND ----------
        legend = self._render_legend()
        body_main += legend
        body_main += '</main>'

        footer = f'<script>{js}</script></body></html>'
        full = head + hero + tiles + toolbar + body_main + footer

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(full)

    # ------------------------------------------------------------------
    # New report helpers
    # ------------------------------------------------------------------

    def _collect_attachment_rows(self, all_reports: List[Dict]) -> List[Dict]:
        rows = []
        for r in all_reports:
            for att in r.get('attachments', []):
                verdict = att.get('verdict')
                rows.append({'email': r['email_folder'], 'attachment': att,
                             'verdict': verdict})
        return rows

    @staticmethod
    def _totals_from_rows(rows: List[Dict]) -> Dict[str, int]:
        t = {'total': len(rows), 'malicious': 0, 'suspicious': 0,
             'clean': 0, 'other': 0}
        for row in rows:
            v = row.get('verdict')
            if v == 'malicious':
                t['malicious'] += 1
            elif v == 'suspicious':
                t['suspicious'] += 1
            elif v == 'clean':
                t['clean'] += 1
            else:
                t['other'] += 1
        return t

    @staticmethod
    def _verdict_for_row(att: Dict) -> str:
        """Return the row's data-verdict attribute value (used for filtering)."""
        v = att.get('verdict')
        if v in ('malicious', 'suspicious', 'clean'):
            return v
        return 'noverdict'

    def _render_email_block(self, email_report: Dict) -> str:
        folder = email_report['email_folder']
        folder_id = self._slug(folder)
        attachments = email_report.get('attachments', [])

        # Per-email summary chips
        summary = email_report.get('summary', {})
        chips = ''
        for key, cls in (('critical', 'crit'), ('high', 'high'),
                          ('medium', 'med'), ('clean', 'clean')):
            n = summary.get(key, 0)
            if n:
                chips += f'<span class="chip chip-{cls}">{n} {key}</span>'

        # Sort attachments worst-first
        verdict_rank = {'malicious': 0, 'suspicious': 1, 'clean': 2}
        attachments = sorted(
            attachments,
            key=lambda a: (verdict_rank.get(a.get('verdict'), 3),
                           -int(a.get('score', 0))),
        )

        out = (
            f'<section class="email" id="email-{folder_id}">'
            f'<header class="email-head">'
            f'<h2>📁 {_html.escape(folder)}</h2>'
            f'<div class="email-chips">{chips}</div>'
            f'</header>'
        )

        # Email-level link
        for link in email_report.get('links', []):
            out += (f'<div class="email-link">🔗 '
                    f'<a href="{_html.escape(link)}" target="_blank" rel="noopener">'
                    f'{_html.escape(link)}</a></div>')

        if 'note' in email_report:
            out += f'<p class="muted"><em>{_html.escape(email_report["note"])}</em></p>'

        # Attachment rows
        if attachments:
            out += '<div class="rows">'
            for att in attachments:
                out += self._render_attachment_row(folder, att)
            out += '</div>'

        # Sub-analyses (collapsed by default)
        header_data = email_report.get('header_analysis', {})
        if header_data and header_data.get('findings'):
            out += ('<details class="subsection"><summary>📨 Email header analysis</summary>'
                    + self._render_header_section(header_data) + '</details>')

        body_link_data = email_report.get('body_link_analysis', {})
        if body_link_data and (body_link_data.get('findings') or
                                body_link_data.get('links_analyzed')):
            out += ('<details class="subsection"><summary>🔗 Body link analysis</summary>'
                    + self._render_body_link_section(body_link_data) + '</details>')

        domain_data = email_report.get('domain_intelligence', {})
        if domain_data and (domain_data.get('findings') or domain_data.get('domains')):
            out += ('<details class="subsection"><summary>🌐 Domain intelligence</summary>'
                    + self._render_domain_section(domain_data) + '</details>')

        out += '</section>'
        return out

    def _render_attachment_row(self, folder: str, att: Dict) -> str:
        filename = Path(att.get('file', '?')).name
        ftype = att.get('type', '?')
        verdict = self._verdict_for_row(att)
        score = att.get('score')
        summary = att.get('summary', '')
        findings = att.get('findings', [])

        # Severity dot color follows verdict (or worst severity if no verdict)
        dot_class = verdict
        if verdict == 'noverdict':
            worst = self._worst_severity(findings)
            if worst == 'CRITICAL':
                dot_class = 'malicious'
            elif worst == 'HIGH':
                dot_class = 'suspicious'
            elif worst in ('MEDIUM', 'LOW'):
                dot_class = 'medium'
            elif worst in ('INFO', 'WARNING', 'ERROR'):
                dot_class = 'noverdict'

        # Searchable text bag
        codes_str = ' '.join(f.get('code', '') for f in findings if f.get('code'))
        search_blob = f'{filename} {ftype} {codes_str} {summary}'.lower()

        # Verdict chip text
        if verdict == 'noverdict':
            chip_text = 'NO VERDICT'
        else:
            chip_text = verdict.upper()
        score_html = (f'<span class="score-pill">{score}/100</span>'
                      if score is not None else '')

        headline = ''
        if summary:
            headline = _html.escape(summary)
        elif findings:
            top = findings[0]
            headline = _html.escape((top.get('message') or
                                      top.get('category') or '')[:140])

        row_id = self._slug(f'{folder}-{filename}')
        head = (
            f'<details class="row" data-verdict="{verdict}" '
            f'data-search="{_html.escape(search_blob, quote=True)}" '
            f'id="file-{row_id}">'
            f'<summary class="row-summary">'
            f'<span class="dot dot-{dot_class}"></span>'
            f'<span class="row-name" title="{_html.escape(filename)}">{_html.escape(filename)}</span>'
            f'<span class="type-pill">{_html.escape(ftype)}</span>'
            f'<span class="row-headline">{headline}</span>'
            f'<span class="verdict-chip verdict-{verdict}">{chip_text}</span>'
            f'{score_html}'
            f'</summary>'
        )

        body = '<div class="row-body">'
        body += self._render_findings_list(findings)

        # IOC table
        iocs = att.get('iocs') or {}
        ioc_rows = [(k, v) for k, v in iocs.items() if v]
        if ioc_rows:
            total = sum(len(v) for _, v in ioc_rows)
            body += (f'<details class="ioc-section"><summary>📌 Extracted IOCs ({total})</summary>'
                     '<table class="ioc-table"><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>')
            for kind, values in ioc_rows:
                for v in values:
                    body += (f'<tr><td>{_html.escape(kind)}</td>'
                             f'<td>{_html.escape(str(v))}</td></tr>')
            body += '</tbody></table></details>'

        # Recommendations
        if att.get('recommendations'):
            body += '<div class="recommendations"><strong>Recommendations:</strong><ul>'
            for rec in att['recommendations']:
                body += f'<li>{_html.escape(str(rec))}</li>'
            body += '</ul></div>'

        # Hashes (collapsed)
        hashes = att.get('hashes') or {}
        if hashes and 'error' not in hashes:
            body += '<details class="subdetails"><summary>🔑 File hashes</summary><div class="hash">'
            for ht, hv in hashes.items():
                body += f'<div><b>{ht.upper()}</b> {_html.escape(str(hv))}</div>'
            body += '</div></details>'

        # Tools used (compact pills)
        tools = att.get('tools_used') or []
        if tools:
            body += '<details class="subdetails"><summary>🔧 Analysis tools</summary><div class="tool-pills">'
            for tool in tools:
                name = tool.get('name', '?')
                status = tool.get('status', '?')
                note = tool.get('note', '') or tool.get('error', '')
                tip = f'{name} {status}' + (f' ({note})' if note else '')
                body += (f'<span class="tool-pill tool-{status}" '
                         f'title="{_html.escape(tip)}">{_html.escape(name)}</span>')
            body += '</div></details>'

        # Statistics
        stats = att.get('statistics') or {}
        if stats:
            body += '<details class="subdetails"><summary>📊 Statistics</summary><div class="stats-grid">'
            for k, v in stats.items():
                body += (f'<div class="stat-row"><span class="stat-key">{_html.escape(str(k))}</span>'
                         f'<span class="stat-val">{_html.escape(str(v))}</span></div>')
            body += '</div></details>'

        body += '</div></details>'
        return head + body

    def _render_findings_list(self, findings: List[Dict]) -> str:
        if not findings:
            return '<p class="muted">No findings.</p>'
        sev_rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3,
                    'WARNING': 3, 'INFO': 4, 'ERROR': 0}
        ordered = sorted(findings, key=lambda f: sev_rank.get(f.get('severity', 'INFO'), 5))

        out = '<div class="findings">'
        for f in ordered:
            sev = f.get('severity', 'INFO')
            code = f.get('code', '')
            info = code_info(code) if code else {}
            title = info.get('title') or f.get('category') or sev
            what = info.get('what', '')
            why = info.get('why', '')
            msg = f.get('message') or ''
            details = f.get('details') or ''
            evidence = f.get('evidence') or {}

            # Collect IOCs for this single finding
            iocs = f.get('iocs') or {}
            ioc_text = ''
            for k, vs in iocs.items():
                if vs:
                    ioc_text += f'<div class="finding-ioc"><b>{_html.escape(k)}:</b> '
                    ioc_text += ', '.join(_html.escape(str(v)) for v in vs)
                    ioc_text += '</div>'

            ev_text = ''
            if evidence:
                bits = []
                for ek in ('object_id', 'stream_path', 'offset', 'excerpt'):
                    if evidence.get(ek) is not None:
                        bits.append(f'<b>{ek}:</b> {_html.escape(str(evidence[ek]))[:240]}')
                if bits:
                    ev_text = '<div class="finding-evidence">' + ' · '.join(bits) + '</div>'

            attck = f.get('mitre_attack') or []
            attck_html = ''
            if attck:
                attck_html = ('<div class="finding-attck">MITRE ATT&amp;CK: '
                              + ', '.join(f'<code>{_html.escape(t)}</code>' for t in attck)
                              + '</div>')

            out += (
                f'<div class="finding sev-{sev}">'
                f'<div class="finding-row">'
                f'<span class="sev-chip sev-chip-{sev}">{sev}</span>'
                f'<span class="finding-title">{_html.escape(title)}</span>'
                + (f'<code class="code-tag">{_html.escape(code)}</code>' if code else '')
                + '</div>'
                f'<div class="finding-msg">{_html.escape(msg)}</div>'
            )
            if what or why or details or ev_text or ioc_text or attck_html:
                out += '<details class="finding-more"><summary>What does this mean?</summary>'
                if what:
                    out += f'<p><b>What:</b> {_html.escape(what)}</p>'
                if why:
                    out += f'<p><b>Why it matters:</b> {_html.escape(why)}</p>'
                if details:
                    out += f'<pre>{_html.escape(str(details)[:1000])}</pre>'
                if ev_text:
                    out += ev_text
                if ioc_text:
                    out += ioc_text
                if attck_html:
                    out += attck_html
                out += '</details>'
            out += '</div>'
        out += '</div>'
        return out

    @staticmethod
    def _worst_severity(findings: List[Dict]) -> str:
        order = {'CRITICAL': 5, 'ERROR': 5, 'HIGH': 4, 'MEDIUM': 3,
                 'WARNING': 2, 'LOW': 2, 'INFO': 1}
        worst, worst_rank = 'INFO', 0
        for f in findings:
            s = f.get('severity', 'INFO')
            r = order.get(s, 0)
            if r > worst_rank:
                worst, worst_rank = s, r
        return worst

    @staticmethod
    def _slug(s: str) -> str:
        out = []
        for ch in s:
            if ch.isalnum() or ch in ('-', '_'):
                out.append(ch)
            else:
                out.append('-')
        return ''.join(out)

    def _render_legend(self) -> str:
        out = ('<section class="legend">'
               '<details><summary>📖 Tool & code legend click to expand</summary>'
               '<div class="legend-body">'
               '<p class="muted">Every finding the analyzer emits has a stable code. '
               'This legend explains what each code means and what each underlying '
               'tool does. Use it to learn what the report is telling you without '
               'reading the source.</p>')

        # Tools section
        out += '<h3>🔧 Analyzers and supporting tools</h3>'
        out += '<div class="legend-tools">'
        for name, info in TOOL_CATALOG.items():
            out += (f'<div class="legend-tool"><div class="legend-tool-head">'
                    f'<code>{_html.escape(name)}</code> '
                    f'<span class="legend-tool-title">{_html.escape(info.get("title", name))}</span>'
                    f'</div>'
                    f'<p><b>What it does:</b> {_html.escape(info.get("what", ""))}</p>'
                    f'<p><b>Why we use it:</b> {_html.escape(info.get("why", ""))}</p>'
                    '</div>')
        out += '</div>'

        # Codes section, grouped by family
        out += '<h3>🏷️ Finding codes</h3>'
        fams = families()
        for family in sorted(fams.keys()):
            out += f'<details class="legend-family"><summary>{_html.escape(family)} '
            out += f'<span class="muted">({len(fams[family])} codes)</span></summary>'
            out += '<table class="legend-table"><thead><tr>'
            out += '<th>Code</th><th>Title</th><th>What</th><th>Why it matters</th>'
            out += '</tr></thead><tbody>'
            for code in fams[family]:
                info = code_info(code)
                out += (f'<tr><td><code>{_html.escape(code)}</code></td>'
                        f'<td>{_html.escape(info.get("title", ""))}</td>'
                        f'<td>{_html.escape(info.get("what", ""))}</td>'
                        f'<td>{_html.escape(info.get("why", ""))}</td></tr>')
            out += '</tbody></table></details>'

        out += '</div></details></section>'
        return out

    def _render_header_section(self, header_data: Dict) -> str:
        """Render the Header Analysis card for the HTML report"""
        html = '<div class="header-card">'
        html += '<h4>📨 Email Header Analysis</h4>'

        # Header summary table
        hd = header_data.get('header_data', {})
        if hd:
            html += '<table class="header-table">'
            fields = [
                ('From', hd.get('from', '')),
                ('To', hd.get('to', '')),
                ('Subject', hd.get('subject', '')),
                ('Date', hd.get('date', '')),
                ('Reply-To', hd.get('reply_to', '')),
                ('Return-Path', hd.get('return_path', '')),
                ('Message-ID', hd.get('message_id', '')),
                ('X-Mailer', hd.get('x_mailer', '')),
                ('Received Hops', str(hd.get('received_count', '')) if hd.get('received_count') else ''),
            ]
            for label, value in fields:
                if value:
                    html += f'<tr><th>{label}</th><td>{value}</td></tr>'
            html += '</table>'

        # Extract SPF/DKIM/DMARC status from findings to show as badges
        auth_status = {'spf': 'none', 'dkim': 'none', 'dmarc': 'none'}
        for finding in header_data.get('findings', []):
            cat = finding.get('category', '').lower()
            msg_lower = finding.get('message', '').lower()
            for check in ['spf', 'dkim', 'dmarc']:
                if check in cat or check in msg_lower:
                    if 'fail' in msg_lower:
                        auth_status[check] = 'fail'
                    elif 'pass' in msg_lower:
                        auth_status[check] = 'pass'

        if any(v != 'none' for v in auth_status.values()):
            html += '<div class="auth-badges">'
            for check in ['spf', 'dkim', 'dmarc']:
                result = auth_status[check]
                badge_class = 'pass' if result == 'pass' else ('fail' if result == 'fail' else 'none')
                html += f'<span class="auth-badge {badge_class}">{check.upper()}: {result.upper()}</span>'
            html += '</div>'

        # Findings
        for finding in header_data.get('findings', []):
            severity = finding.get('severity', 'INFO')
            category = finding.get('category', '')
            message = finding.get('message', '')
            details = finding.get('details', '')
            html += f'<div class="finding {severity}">'
            html += f'<strong>[{severity}]</strong> '
            if category:
                html += f'<strong>{category}:</strong> '
            html += message
            if details:
                html += f'<pre>{details[:500]}</pre>'
            html += '</div>'

        html += '</div>'
        return html

    def _render_body_link_section(self, body_link_data: Dict) -> str:
        """Render the Body Link Analysis card for the HTML report"""
        html = '<div class="body-link-card">'
        html += '<h4>🔗 Body Link Analysis</h4>'

        # Links analyzed table
        links = body_link_data.get('links_analyzed', [])
        if links:
            html += '<table class="link-table">'
            html += '<tr><th>Display Text</th><th>Actual URL (href)</th><th>Mismatch</th></tr>'
            for link_info in links:
                display = link_info.get('display_text', 'N/A')[:80]
                href = link_info.get('href', 'N/A')
                mismatch = link_info.get('mismatch', False)
                mismatch_class = 'mismatch-yes' if mismatch else 'mismatch-no'
                mismatch_text = 'YES - MISMATCH' if mismatch else 'No'
                html += f'<tr><td>{display}</td><td>{href}</td>'
                html += f'<td class="{mismatch_class}">{mismatch_text}</td></tr>'
            html += '</table>'

        # Findings
        for finding in body_link_data.get('findings', []):
            severity = finding.get('severity', 'INFO')
            category = finding.get('category', '')
            message = finding.get('message', '')
            details = finding.get('details', '')
            html += f'<div class="finding {severity}">'
            html += f'<strong>[{severity}]</strong> '
            if category:
                html += f'<strong>{category}:</strong> '
            html += message
            if details:
                html += f'<pre>{details[:500]}</pre>'
            html += '</div>'

        html += '</div>'
        return html

    def _render_domain_section(self, domain_data: Dict) -> str:
        """Render the Domain Intelligence card for the HTML report"""
        html = '<div class="domain-card">'
        html += '<h4>🌐 Domain Intelligence</h4>'

        # Domain entries
        domains = domain_data.get('domains', {})
        for domain_name, info in domains.items():
            html += f'<div class="domain-entry">'
            html += f'<div class="domain-name">{domain_name}</div>'

            if info.get('whois'):
                whois_data = info['whois']
                if whois_data.get('creation_date'):
                    html += f'<div class="domain-detail"><span class="label">Created:</span> {whois_data["creation_date"]}</div>'
                if whois_data.get('age_days') is not None:
                    age = whois_data['age_days']
                    age_color = '#dc3545' if age < 30 else ('#ffc107' if age < 90 else '#28a745')
                    html += f'<div class="domain-detail"><span class="label">Age:</span> <span style="color:{age_color};font-weight:bold;">{age} days</span></div>'
                if whois_data.get('registrar'):
                    html += f'<div class="domain-detail"><span class="label">Registrar:</span> {whois_data["registrar"]}</div>'
                if whois_data.get('error'):
                    html += f'<div class="domain-detail"><span class="label">WHOIS:</span> <span style="color:#856404;">{whois_data["error"][:100]}</span></div>'

            if info.get('dns'):
                dns_data = info['dns']
                if dns_data.get('A'):
                    html += f'<div class="domain-detail"><span class="label">A Records:</span> {", ".join(dns_data["A"][:3])}</div>'
                if dns_data.get('MX'):
                    html += f'<div class="domain-detail"><span class="label">MX Records:</span> {", ".join(str(r) for r in dns_data["MX"][:3])}</div>'
                if dns_data.get('NS'):
                    html += f'<div class="domain-detail"><span class="label">NS Records:</span> {", ".join(dns_data["NS"][:3])}</div>'

            if info.get('ssl'):
                ssl_info = info['ssl']
                if ssl_info.get('issuer'):
                    issuer = ssl_info['issuer']
                    issuer_str = issuer.get('organizationName', issuer.get('commonName', str(issuer))) if isinstance(issuer, dict) else str(issuer)
                    html += f'<div class="domain-detail"><span class="label">SSL Issuer:</span> {issuer_str}</div>'
                if ssl_info.get('error'):
                    html += f'<div class="domain-detail"><span class="label">SSL:</span> <span style="color:#dc3545;">{ssl_info["error"][:100]}</span></div>'

            html += '</div>'

        # Findings
        for finding in domain_data.get('findings', []):
            severity = finding.get('severity', 'INFO')
            category = finding.get('category', '')
            message = finding.get('message', '')
            details = finding.get('details', '')
            html += f'<div class="finding {severity}">'
            html += f'<strong>[{severity}]</strong> '
            if category:
                html += f'<strong>{category}:</strong> '
            html += message
            if details:
                html += f'<pre>{details[:500]}</pre>'
            html += '</div>'

        html += '</div>'
        return html

    def generate_json_report(self, all_reports: List[Dict], output_file: Path):
        """Generate a JSON report"""
        report_data = {
            'generated': datetime.now().isoformat(),
            'summary': {
                'total_emails': len(all_reports),
                'total_attachments': sum(r['summary']['total_files'] for r in all_reports),
                'total_critical': sum(r['summary']['critical'] for r in all_reports),
                'total_high': sum(r['summary']['high'] for r in all_reports),
                'total_medium': sum(r['summary']['medium'] for r in all_reports),
                'total_clean': sum(r['summary']['clean'] for r in all_reports)
            },
            'emails': all_reports
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)

    def analyze_all(self):
        """Analyze all email folders in the root directory"""
        if not self.root_folder.exists():
            print(f"Error: Folder {self.root_folder} does not exist")
            return

        all_reports = []

        # Iterate through each subfolder (email folder)
        for email_folder in self.root_folder.iterdir():
            if email_folder.is_dir():
                print(f"Analyzing email folder: {email_folder.name}")
                report = self.analyze_email_folder(email_folder)
                all_reports.append(report)

                # Print summary for this email
                summary = report['summary']
                print(f"  Files: {summary['total_files']}, "
                      f"Critical: {summary['critical']}, "
                      f"High: {summary['high']}, "
                      f"Medium: {summary['medium']}, "
                      f"Clean: {summary['clean']}")

        if not all_reports:
            print("No email folders found to analyze")
            return

        # Generate reports
        print("\nGenerating reports...")

        html_report = self.root_folder / f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        json_report = self.root_folder / f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        self.generate_html_report(all_reports, html_report)
        self.generate_json_report(all_reports, json_report)

        print(f"\n[+] Analysis complete!")
        print(f"    HTML Report: {html_report}")
        print(f"    JSON Report: {json_report}")

        # Print summary
        total_critical = sum(r['summary']['critical'] for r in all_reports)
        total_high = sum(r['summary']['high'] for r in all_reports)

        if total_critical > 0:
            print(f"\n[!] WARNING: {total_critical} CRITICAL findings detected!")
        if total_high > 0:
            print(f"[!] WARNING: {total_high} HIGH risk findings detected!")


def main():
    if len(sys.argv) < 2:
        print("Usage: python email_attachment_analyzer.py <folder_path>")
        print("\nThis script analyzes email attachments for potential security threats.")
        print("Folder structure expected:")
        print("  <folder_path>/")
        print("    email1/")
        print("      attached_files/")
        print("        attachment1.pdf")
        print("        attachment2.doc")
        print("    email2/")
        print("      attached_files/")
        print("        ...")
        sys.exit(1)

    folder_path = sys.argv[1]

    # Startup mode selection
    print("\n" + "="*60)
    print("  Barbarian Phishing")
    print("="*60)
    if CUSTOM_TOOLS_AVAILABLE:
        print("  [+] Custom security tools: LOADED")
    else:
        print("  [-] Custom security tools: NOT AVAILABLE")
    print()
    print("  Select analysis mode:")
    print("  [1] Normal mode - headers in attached_files/, body.html in email folder")
    print("  [2] EML mode   - parse .eml file to extract headers, body, and attachments")
    print()

    while True:
        choice = input("  Enter choice (1 or 2): ").strip()
        if choice in ('1', '2'):
            break
        print("  Invalid choice. Please enter 1 or 2.")

    mode = 'normal' if choice == '1' else 'eml'
    print(f"\n  [*] Running in {'Normal' if mode == 'normal' else 'EML'} mode...\n")

    analyzer = AttachmentAnalyzer(folder_path, mode=mode)
    analyzer.analyze_all()


if __name__ == '__main__':
    main()
