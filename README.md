# Barbarian Phishing

Automated security analysis tool for email attachments designed for cybersecurity analysts. Analyzes PDFs, Office documents, headers, domains and images for malicious content using industry-standard tools.
Please use with Caution, this tool will NOT detect everything that is used out there in the wild. 
Additionaly, social engineering detection is not intigrated...

---

## How to run it

### 1. Install

```bash
git clone https://github.com/Doomed5G/Barbarian-phishing.git
cd Barbarian-phishing

# Windows
py -3.13 -m pip install -r requirements.txt

# Linux / macOS
python3 -m pip install -r requirements.txt
```

That installs everything the analyzers need: `pikepdf` (PDF), `oletools` + `olefile` + `msoffcrypto-tool` (Office/RTF/encrypted), `defusedxml` (safe XML), `puremagic` (magic-byte file ID), `Pillow` (image forensics).

> **Windows: use `py -3.13`, not the Microsoft Store `python3`.** The Store's `python3`
> is a *separate* interpreter with its own empty `site-packages`. If you install with one
> interpreter and run with another, the report will claim packages like `pikepdf` or
> `puremagic` are "not installed" even though they are. Use `py -3.13` (or `py -3`) for
> both install **and** run so they hit the same interpreter. Check with
> `py -3.13 -m pip show pikepdf`.

### 2. Lay out your input

The script analyzes a **root folder** that contains one subfolder per email. You pick one of two layouts for that subfolder:

> **Why this exact layout?** This tool is paired with another script (the upstream one that ingests your mailboxes / queues and prepares samples for analysis). That upstream script writes its output in this exact shape, and Barbarian Phishing is wired to consume it directly. If you want to feed it a different shape, see [Customizing the input shape](#customizing-the-input-shape) below.

#### Normal mode (one folder per email, headers + body + attachments as separate files)

```
emails_to_analyze/                 <-- this is the path you pass on the CLI
├── email_001/
│   ├── attached_files/
│   │   ├── headers.txt            <-- raw email headers, one per file
│   │   ├── invoice.pdf            <-- any attachments alongside
│   │   └── document.docx
│   ├── body.html                  <-- preferred, used by body link analyzer
│   └── body.txt                   <-- fallback if no body.html
├── email_002/
│   └── attached_files/
│       └── ...
└── link.txt                       <-- optional, root-level (see below)
```

- `attached_files/headers.txt` is the dump of the email's RFC 5322 headers. The header analyzer reads it directly.
- `body.html` is preferred over `body.txt`; the body link analyzer wants HTML so it can compare display text to actual hrefs.
- Attachment filenames don't matter, only their extensions. The router in `analyze_file` dispatches by extension.

#### EML mode (one `.eml` file per email)

```
emails_to_analyze/
├── email_001/
│   └── message.eml                <-- name doesn't matter; first .eml in the folder wins
├── email_002/
│   └── case_2024_001.eml
└── link.txt                       <-- optional, root-level
```

In EML mode the script unpacks each `.eml` itself: it parses headers, picks the HTML body (falls back to plain text), extracts every attachment to a fresh `attached_files/` subdir under the email folder, and pulls URLs from the body into a per-email `link.txt`. From that point onward analysis is identical to Normal mode.

#### `link.txt` (optional, both modes)

A plain-text file with one URL per line. Two scopes:

- `emails_to_analyze/link.txt` (root) shared list of URLs to enrich with `domain_intel` for *every* email in the run.
- `emails_to_analyze/email_001/link.txt` (per-email) URLs scoped to that email only. EML mode writes this automatically from the body's hrefs.

### 3. Run the analyzer

```bash
# Windows
py -3.13 barbarian-phishing.py path\to\emails_to_analyze

# Linux / macOS
python3 barbarian-phishing.py path/to/emails_to_analyze
```

You'll be prompted at startup:

```
  Select analysis mode:
  [1] Normal mode - headers in attached_files/, body.html in email folder
  [2] EML mode   - parse .eml file to extract headers, body, and attachments

  Enter choice (1 or 2):
```

Pick the layout you used. The mode applies to the **whole run** — you can't mix Normal and EML email folders in one input root.

### 4. Find the results

Two files land **inside the input root** (next to the email folders), timestamped so consecutive runs don't overwrite each other:

```
emails_to_analyze/
├── analysis_report_YYYYMMDD_HHMMSS.html     <-- open in browser
├── analysis_report_YYYYMMDD_HHMMSS.json     <-- machine-readable
├── email_001/...
└── email_002/...
```

- The **HTML** is the interactive triage dashboard described in [Reports](#reports). Single self-contained file dark theme by default, filter pills, search box, collapsible per-attachment rows, in-report tool & code legend.
- The **JSON** is the same data structured for downstream consumption (SIEM, SOAR, scripts).

The console output also gives you a one-line summary per email and the total counts at the end.

### Customizing the input shape

If the upstream script that feeds you ever changes its layout, or you want to plug Barbarian Phishing into a different pipeline, these are the four hooks to edit. All live in [barbarian-phishing.py](barbarian-phishing.py).

| Hook | Lines (approx.) | What it controls |
|---|---|---|
| `analyze` (entry point) | top of `AttachmentAnalyzer` | how the root folder is iterated and which subfolders it considers email folders. |
| `analyze_email_folder` | line 871 | per-email Normal-mode contract: where to find `attached_files/`, `headers.txt`, `body.html`, `link.txt`. |
| `_find_eml_file` + `_parse_eml` | lines 1000 + 1007 | EML-mode contract: what counts as the `.eml` (first match by extension), how attachments and the body are pulled out, and where they are written. |
| `analyze_file` | line 774 | per-file routing by extension to the PDF / Office / image / archive / script analyzers. Add new extensions or redirect existing ones here. |

For example, if your upstream pairs each email with a sidecar `meta.json` and you want to surface its fields in the report, the simplest place is `analyze_email_folder` read the JSON, attach it to the per-email report dict, and the HTML/JSON renderers already serialize unknown keys.

If you want to drop the interactive prompt and run unattended, the prompt lives in `__main__` (bottom of the file, around line 1768). Replace it with an arg parser or hard-code `mode='eml'` / `mode='normal'`.

---

## What's inside

The analysis stack is fully native Python: no subprocess shells to external scripts, no `.py` files imported from PATH. Every analyzer is a normal class importable from [tools/custom/](tools/custom/).

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

### HTML report (interactive triage dashboard)

Single self-contained file (no external assets). Dark theme by default.

- **Hero + tiles** at the top: counts of malicious / suspicious / clean / no-verdict attachments
- **Sticky toolbar**: filter pills (All / Malicious / Suspicious / Clean / No verdict), free-text search across filename + code + message, Expand all / Collapse all
- **One row per attachment**, grouped by email and sorted worst-first. Each row is collapsed by default; click to drill in.
- **Inside a row**: findings (each with severity chip, friendly title, and a "What does this mean?" sub-collapsible explaining what + why), extracted IOCs, recommendations, file hashes, analysis tools used, statistics
- **Per-email subsections** (header / body link / domain intel) are also collapsed by default, so they don't dominate the page
- **🌙 / ☀ theme toggle** in the header, persists in localStorage
- **📖 Tool & code legend** at the bottom (also collapsed): explains every analyzer and lists every finding code grouped by family with plain-English **What** and **Why it matters** columns

### JSON report (machine-readable)

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

## Testing

```bash
# Windows
py -3.13 -m pip install -r requirements-dev.txt
py -3.13 -m pytest tests/ -v

# Linux / macOS
python3 -m pip install -r requirements-dev.txt
python3 -m pytest tests/ -v
```

The suite covers IOC extraction, the scoring engine, EML parsing, the PDF analyzer (against the [test_pdfs/](test_pdfs/) fixtures), and the Office analyzer (against synthetic OOXML zips assembled in-memory; no malware-corpus files committed). 47 tests at time of writing, all green on Windows / Python 3.13–3.14 with `pikepdf` and `oletools` installed.

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


## License

This tool is for authorized security analysis only. Ensure you have permission to analyze all files.

## Resources

- pikepdf: https://pikepdf.readthedocs.io/
- oletools: https://github.com/decalage2/oletools
- msoffcrypto-tool: https://github.com/nolze/msoffcrypto-tool
- MITRE ATT&CK: https://attack.mitre.org/
- OWASP: https://owasp.org/
- SANS Internet Storm Center: https://isc.sans.edu/
