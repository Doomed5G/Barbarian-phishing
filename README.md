# Barbarian Phishing

Automated security analysis tool for email attachments designed for cybersecurity analysts. Analyzes PDFs, Office documents, and images for malicious content using industry-standard tools.
Please use with Caution, this tool will NOT detect everything that is used out there in the wild. 
Additionaly, social engineering detection is not intigrated...

---

## Quick start

```bash
git clone https://github.com/Doomed5G/Barbarian-phishing.git
cd Barbarian-phishing
pip install -r requirements.txt
python barbarian-phishing.py path/to/emails_to_analyze
```

You'll be asked to choose a mode:

- **Normal mode** each email folder contains an `attached_files/` directory with a `headers.txt` plus the attachments, and a `body.html` (or `body.txt`) at the email-folder root.
- **EML mode** each email folder contains a `.eml` file; the script parses headers, body, and attachments from it directly.

Reports land next to the input directory.

---

## What's inside

The analysis stack is fully native Python no subprocess shells to external scripts, no `.py` files imported from PATH. Every analyzer is a normal class importable from [tools/custom/](tools/custom/).

| Module | What it does |
|---|---|
| [tools/custom/pdf_analyzer.py](tools/custom/pdf_analyzer.py) | PDF object-graph walker built on `pikepdf` (libqpdf bindings). Resolves `/OpenAction` and `/AA` triggers, decompresses streams, extracts JS source and scans for eval / shellcode / known CVE markers, recurses into `/ObjStm`, walks the `/Names` → `/EmbeddedFiles` tree, parses XFA forms with `defusedxml`, detects encryption (with weak-password unlock + email-body password hints), and flags polyglots at the byte level. |
| [tools/custom/office_analyzer.py](tools/custom/office_analyzer.py) | Office analyzer that dispatches by container: OLE2 (`.doc/.xls/.ppt/.msg`), OOXML (`.docx/.xlsx/.pptx` + `.docm/.xlsm/.pptm`), RTF, encrypted (any). Built on `oletools` as a **library** (not subprocess), `olefile`, `msoffcrypto-tool`, and `defusedxml`. Iterates **every** macro module no early-break and runs `detect_autoexec` / `detect_suspicious` / `detect_patterns` plus our own IOC extractor over each. Catches DDE/DDEAUTO field codes, external-template injection (CVE-2017-0199), embedded OLE objects with PE payloads, RTF Equation.3 (CVE-2017-11882), Excel 4.0 (XLM) macros, and weakly-encrypted documents. |
| [tools/custom/header_analyzer.py](tools/custom/header_analyzer.py) | Email-header forensics: SPF / DKIM / DMARC, From-vs-Reply-To-vs-Return-Path mismatches, Received-chain hop tracing, suspicious mail-client fingerprinting. |
| [tools/custom/body_link_analyzer.py](tools/custom/body_link_analyzer.py) | Deceptive-link detection in HTML email bodies: display-vs-href mismatches, URL shorteners, homograph attacks, `javascript:` / `data:` URIs, hidden iframes, raw-IP URLs, credential-harvesting paths. |
| [tools/custom/domain_intel.py](tools/custom/domain_intel.py) | Domain reputation: WHOIS age, DNS records, SSL certificate validity, suspicious TLDs, brand-impersonation IDN homographs. |
| [tools/custom/image_forensics.py](tools/custom/image_forensics.py) | Image forensics: ELA (error-level analysis), EXIF consistency, embedded-thumbnail comparison, EXIF-stripping detection, LSB-steganography statistical scan. |
| [tools/custom/attachment_analyzer.py](tools/custom/attachment_analyzer.py) | Universal handler for the file types the core doesn't cover: archives (zip-bomb detection), scripts (`.js/.vbs/.ps1/.bat/.cmd/.wsf/.hta`), executables, HTML, LNK shortcuts. |
| [tools/custom/iocs.py](tools/custom/iocs.py) | Shared IOC extractor + string deobfuscator (Chr / concat / StrReverse / hex / base64). Reusable across PDF JS, VBA source, RTF, scripts. |
| [tools/custom/scoring.py](tools/custom/scoring.py) | Correlation-based scoring engine. Sums per-code base scores, applies bonuses when sets co-occur (e.g. `/OpenAction` + `/JS` + `eval()` ⇒ malicious), produces `verdict` + `score` 0–100 + one-line summary. |
| [tools/custom/code_catalog.py](tools/custom/code_catalog.py) | Plain-English explanation per finding code. Powers the row titles **and** the in-report legend. |

---

## What it detects

### PDF
- `/JavaScript`, `/Launch`, `/SubmitForm`, `/ImportData`, `/GoToR`, `/GoToE`, `/URI`, `/Hide`, `/RichMediaExecute`, `/Named` actions
- `/OpenAction` and `/AA` auto-execute triggers (catalog and per-page)
- JS body content: `eval()`, `unescape()`, `String.fromCharCode`, `app.launchURL`, shellcode markers, `util.printf`, and CVE fingerprints (Collab.collectEmailInfo, Collab.getIcon, getAnnots, media.newPlayer)
- AcroForm + XFA `<script>` blocks
- Embedded files (with PE / script payload escalation)
- Suspicious stream filters: `/JBIG2Decode`, chained `/ASCII85Decode`, JS hidden inside `/ObjStm`
- Encrypted PDFs (with weak-password unlock from a small dictionary + email-body password hints)
- Byte-level polyglots (`MZ`/`PK\x03\x04` after `%%EOF`, second `%PDF-` headers)

### Office
- VBA macros every module enumerated, every auto-exec / shell / download / suspicious / pattern hit collected
- Obfuscation heuristics on VBA source (Chr / concat density)
- DDE and DDEAUTO field codes (only when in real `<w:fldChar>` / `<w:instrText>` context fewer false positives than scanning for the literal word)
- External-relationship abuse: `attachedTemplate` / `oleObject` over HTTP (CVE-2017-0199 family)
- Embedded OLE objects (`*/embeddings/oleObject*.bin`), with PE / script payload escalation
- Remote-image relationships (NTLM-leak / tracking pixels)
- RTF embedded OLE objects: `Equation.3` (CVE-2017-11882 / 2018-0802), `OLE2Link` (CVE-2017-0199), `Package` (with PE payload detection)
- Excel 4.0 (XLM) macros via `VBA_Parser.detect_xlm_macros()`
- Encrypted documents (with weak-password unlock + email-body hints)

### Email headers
- SPF / DKIM / DMARC failures (DMARC fail = CRITICAL, SPF fail = HIGH, soft-fail = MEDIUM)
- From / Reply-To / Return-Path domain mismatches
- Received-chain hop tracing originating server, missing or excessive (>10) hops
- Suspicious mail-client fingerprints (PHPMailer, Microsoft CDO, The Bat!, ZuckMail, etc.)

### HTML body links
- Display-text vs. actual `href` mismatches
- URL shorteners (bit.ly, tinyurl, t.co, goo.gl, …)
- Homograph attacks via non-ASCII display text
- `javascript:` and `data:` URI protocols
- Suspicious query parameters (`password=`, `credentials=`, `token=`)
- Hidden iframes (`display:none`, zero-dimension)
- Raw-IP URLs and credential-harvesting paths (`/login`, `/signin`, `/verify`)

### Domains
- WHOIS age (< 30 days = HIGH, < 90 = MEDIUM)
- DNS records (missing A/MX = HIGH, missing SPF TXT = MEDIUM)
- SSL/TLS certificate validity (expired, self-signed, hostname mismatch)
- Suspicious TLDs (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.top`, `.xyz`, `.click`, `.link`, …)
- IDN homograph and brand-impersonation (paypal/google/microsoft/apple/…)

### Images
- **Error Level Analysis (ELA)** re-saves the JPEG at quality 95 and compares pixel arrays; localized differences indicate edited regions, global anomalies indicate re-compression
- **EXIF metadata consistency** flags editing-software signatures (Photoshop, GIMP, Paint), inconsistent date fields, and surfaces GPS data when present
- **Embedded thumbnail comparison** diffs the JPEG-embedded thumbnail against the main image; large pixel-difference scores indicate post-thumbnail editing
- **EXIF stripping detection** flags JPEGs whose EXIF block is gone (LOW) or whose camera-info fields are present but date fields removed (MEDIUM)
- **LSB statistical analysis** least-significant-bit distribution and transition deviation; balanced LSB ratios with low variance suggest steganographic payloads
- **Polyglot detection** embedded ZIP/PDF/EXE signatures inside images (handled by [tools/custom/attachment_analyzer.py](tools/custom/attachment_analyzer.py) magic-byte validation, runs on every file regardless of extension)

---

## Reports

Two files are written next to the input directory: `analysis_report_YYYYMMDD_HHMMSS.html` and `.json`.

### HTML report interactive triage dashboard

Single self-contained file (no external assets). Dark theme by default.

- **Hero + tiles** at the top: counts of malicious / suspicious / clean / no-verdict attachments
- **Sticky toolbar**: filter pills (All / Malicious / Suspicious / Clean / No verdict), free-text search across filename + code + message, Expand all / Collapse all
- **One row per attachment**, grouped by email and sorted worst-first. Each row collapsed by default click to drill in.
- **Inside a row**: findings (each with severity chip, friendly title, and a "What does this mean?" sub-collapsible explaining what + why), extracted IOCs, recommendations, file hashes, analysis tools used, statistics
- **Per-email subsections** (header / body link / domain intel) are also collapsed by default they don't dominate the page
- **🌙 / ☀ theme toggle** in the header, persists in localStorage
- **📖 Tool & code legend** at the bottom (also collapsed): explains every analyzer and lists every finding code grouped by family with plain-English **What** and **Why it matters** columns

### JSON report machine-readable

Each attachment's analysis dict carries the standard fields (`file`, `type`, `timestamp`, `hashes`, `findings`, `tools_used`) plus the new structured output:

```json
{
  "verdict": "malicious",
  "score": 70,
  "summary": "PDF auto-runs JavaScript on open.",
  "iocs": { "urls": [...], "ips": [...], "domains": [...], "hashes_sha256": [...] },
  "statistics": { "page_count": 1, "object_count": 7, "is_encrypted": false },
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "Launch Action",
      "code": "PDF.ACTION_LAUNCH",
      "message": "Launch Action reachable via page 1 annotation /A.",
      "evidence": { "object_id": 5, "excerpt": "..." },
      "iocs": { "paths": [...] },
      "mitre_attack": ["T1204.002"],
      "confidence": 0.9
    }
  ]
}
```

### Verdict and severity

- **Verdict** is per-file: `malicious` (score ≥ 70), `suspicious` (≥ 30), or `clean`. The score is computed from per-code base values plus correlation bonuses.
- **Severity** is per-finding (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` / `WARNING` / `ERROR`) and feeds the chip color in the HTML.

---

## Folder structure expected

```
emails_to_analyze/
├── email_001/
│   ├── attached_files/
│   │   ├── headers.txt          # Normal mode
│   │   ├── invoice.pdf
│   │   └── document.docx
│   └── body.html                # Normal mode (or body.txt)
├── email_002/
│   └── message.eml              # EML mode
└── link.txt                     # Optional extra URLs to feed to domain_intel
```

The script asks you which mode at launch. You can mix pick Normal or EML for the whole run.

---

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

The suite covers IOC extraction, the scoring engine, the PDF analyzer (against the [test_pdfs/](test_pdfs/) fixtures), and the Office analyzer (against synthetic OOXML zips assembled in-memory no malware-corpus files committed). 45 tests at time of writing, all green on Windows / Python 3.13–3.14 with `pikepdf` and `oletools` installed.

---

## Architecture notes

- All previous Didier Stevens / oletools subprocess scripts (`pdf-parser.py`, `oledump.py`, `oleid.py`, `olevba.py`) have been removed. The same algorithms run in-process via `pikepdf` and `oletools` as proper Python libraries faster, structured output, no PATH-lookup or stdout-scraping.
- The optional `XLMMacroDeobfuscator` package, if installed, will be used automatically for Excel 4.0 deobfuscation. Without it, XLM presence is still flagged, just not deobfuscated.
- Image forensics requires `Pillow` (in `requirements.txt`); without it, EXIF/ELA/steganography checks degrade gracefully and emit a setup warning.
- Optional `puremagic` (in `requirements.txt`) provides magic-byte file-type validation `python-magic` is **not** used, since on Windows it requires shipping `libmagic.dll`.

---

## Limitations

- Cannot detect zero-day exploits or novel obfuscation that no rule fires on.
- Strongly-encrypted documents stay opaque (we try a small dictionary + body hints; that's it).
- WHOIS / DNS / SSL checks in `domain_intel` make live network calls and are best-effort.
- Image steganography detection is heuristic; LSB checks reduce false negatives but do not prove a payload is present.

## Security considerations

- Run in an isolated environment when handling unknown attachments.
- Don't open flagged files outside a sandbox.
- Update `oletools` / `pikepdf` regularly both ship rule and parser improvements.
- Manual review remains required for any `malicious` verdict before action.

## Contributing

Useful directions:
- Additional finding rules + entries in [tools/custom/code_catalog.py](tools/custom/code_catalog.py).
- VirusTotal / threat-intel API enrichment in `domain_intel`.
- YARA-rule integration over decoded JS / VBA / RTF payloads.
- OneNote (`.one`) full parsing currently only embedded-PE byte scan.
- More test fixtures in [test_pdfs/](test_pdfs/) and a `test_office/` corpus.

## License

This tool is for authorized security analysis only. Ensure you have permission to analyze all files.

## Resources

- pikepdf: https://pikepdf.readthedocs.io/
- oletools: https://github.com/decalage2/oletools
- msoffcrypto-tool: https://github.com/nolze/msoffcrypto-tool
- MITRE ATT&CK: https://attack.mitre.org/
- OWASP: https://owasp.org/
- SANS Internet Storm Center: https://isc.sans.edu/
