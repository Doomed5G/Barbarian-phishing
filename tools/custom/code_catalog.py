#!/usr/bin/env python3
"""
Human-readable catalog for finding codes.

Every analyzer emits stable codes like ``PDF.ACTION_LAUNCH`` or
``OFFICE.VBA_AUTOEXEC``. The HTML report uses this catalog to
(a) render a friendly title next to the raw code, and
(b) build a "Tool & code legend" section so non-experts understand
each finding without reading our source.
"""

from typing import Dict, TypedDict


class CodeInfo(TypedDict, total=False):
    title: str          # short noun phrase: "Launch action"
    what: str           # plain-English: "PDF tries to run an external program."
    why: str            # why an analyst should care
    family: str         # group key for the legend (e.g. "PDF actions")


# Friendly descriptions per finding code. Any code not in this catalog
# still renders, just with the raw code as its title.
CODE_CATALOG: Dict[str, CodeInfo] = {
    # ===== PDF: actions =====
    "PDF.ACTION_JAVASCRIPT": {
        "title": "JavaScript action",
        "what": "PDF defines a JavaScript action. Some readers will execute it on open or click.",
        "why":  "Real-world PDF malware almost always lives in JavaScript. This alone is suspicious; combined with /OpenAction it auto-runs.",
        "family": "PDF actions",
    },
    "PDF.ACTION_LAUNCH": {
        "title": "Launch action",
        "what": "PDF defines a /Launch action that asks the reader to start an external program.",
        "why":  "There is no benign reason for a normal document to launch an executable. This is almost always malicious.",
        "family": "PDF actions",
    },
    "PDF.ACTION_SUBMITFORM": {
        "title": "Form submit action",
        "what": "PDF can post form data to a URL.",
        "why":  "Used by phishing PDFs to harvest credentials. Inspect the destination URL.",
        "family": "PDF actions",
    },
    "PDF.ACTION_IMPORTDATA": {
        "title": "ImportData action",
        "what": "PDF imports data from an external file at runtime.",
        "why":  "Allows pulling content from arbitrary local/remote files used for staging.",
        "family": "PDF actions",
    },
    "PDF.ACTION_GOTOR": {
        "title": "Remote GoTo",
        "what": "Action navigates to a remote PDF/URL.",
        "why":  "Can pull a second-stage PDF from an attacker server.",
        "family": "PDF actions",
    },
    "PDF.ACTION_GOTOE": {
        "title": "Embedded GoTo",
        "what": "Action navigates into an embedded file inside this PDF.",
        "why":  "Often pairs with /EmbeddedFile to launch hidden payloads.",
        "family": "PDF actions",
    },
    "PDF.ACTION_URI": {
        "title": "URI action",
        "what": "PDF action opens a URL.",
        "why":  "Common in phishing check the actual destination, not the visible link text.",
        "family": "PDF actions",
    },
    "PDF.ACTION_NAMED": {
        "title": "Named action",
        "what": "Action invokes a named viewer command (e.g. Print, NextPage).",
        "why":  "Mostly benign on its own; flagged for completeness.",
        "family": "PDF actions",
    },
    "PDF.ACTION_HIDE": {
        "title": "Hide action",
        "what": "Action hides or shows annotations.",
        "why":  "Used together with /JS to mask malicious controls visually.",
        "family": "PDF actions",
    },
    "PDF.ACTION_RICHMEDIAEXECUTE": {
        "title": "RichMediaExecute action",
        "what": "Action executes a script inside an embedded RichMedia (Flash/3D) annotation.",
        "why":  "Legacy attack surface historically used for sandbox escapes.",
        "family": "PDF actions",
    },

    # ===== PDF: triggers =====
    "PDF.OPENACTION": {
        "title": "OpenAction trigger",
        "what": "PDF specifies an action that runs automatically when the document is opened.",
        "why":  "Combined with a JavaScript or Launch action, the user does not have to click anything for the payload to fire.",
        "family": "PDF triggers",
    },
    "PDF.AUTOACTION": {
        "title": "Additional actions (/AA)",
        "what": "PDF defines /AA additional-action triggers (on the catalog or a page).",
        "why":  "/AA can fire on document close, page open, focus change, etc. another auto-run vector.",
        "family": "PDF triggers",
    },

    # ===== PDF: JS content =====
    "PDF.JS_EVAL": {
        "title": "JS eval()",
        "what": "Embedded JavaScript calls eval().",
        "why":  "Almost universal in obfuscated/malicious PDF JS.",
        "family": "PDF JavaScript",
    },
    "PDF.JS_UNESCAPE": {
        "title": "JS unescape()",
        "what": "Embedded JavaScript uses unescape() a classic obfuscation primitive.",
        "why":  "Legitimate JS rarely needs it; common in shellcode-staging PDFs.",
        "family": "PDF JavaScript",
    },
    "PDF.JS_FROMCHARCODE": {
        "title": "JS String.fromCharCode()",
        "what": "JavaScript builds strings from numeric character codes.",
        "why":  "Obfuscation marker used to hide URLs/commands from static scanners.",
        "family": "PDF JavaScript",
    },
    "PDF.JS_LAUNCH_URL": {
        "title": "JS app.launchURL()",
        "what": "JavaScript opens a URL via the reader API.",
        "why":  "Direct phishing channel; the URL is the IOC.",
        "family": "PDF JavaScript",
    },
    "PDF.JS_LONG_LITERAL": {
        "title": "JS long string literal",
        "what": "JavaScript contains an unusually long string literal.",
        "why":  "Often packed shellcode or base64 payload.",
        "family": "PDF JavaScript",
    },
    "PDF.JS_SHELLCODE": {
        "title": "JS shellcode markers",
        "what": "JavaScript contains hex/unicode escape patterns characteristic of shellcode.",
        "why":  "Strong indicator of memory-corruption exploit attempt.",
        "family": "PDF JavaScript",
    },
    "PDF.JS_UTIL_PRINTF": {
        "title": "JS util.printf",
        "what": "JavaScript calls Adobe's util.printf historically vulnerable (CVE-2008-2992).",
        "why":  "Pattern shows up in old-but-still-circulating exploit kits.",
        "family": "PDF JavaScript",
    },
    "PDF.JS_CVE_COLLAB_EMAIL": {
        "title": "CVE-2007-5659",
        "what": "JavaScript calls Collab.collectEmailInfo the marker for CVE-2007-5659.",
        "why":  "Direct fingerprint of a known Adobe Reader exploit.",
        "family": "PDF JavaScript",
    },
    "PDF.JS_CVE_COLLAB_GETICON": {
        "title": "CVE-2009-0927",
        "what": "JavaScript calls Collab.getIcon marker for CVE-2009-0927.",
        "why":  "Known Reader exploit fingerprint.",
        "family": "PDF JavaScript",
    },
    "PDF.JS_CVE_GETANNOTS": {
        "title": "CVE-2009-1492",
        "what": "JavaScript calls getAnnots marker for CVE-2009-1492.",
        "why":  "Known Reader exploit fingerprint.",
        "family": "PDF JavaScript",
    },
    "PDF.JS_CVE_NEWPLAYER": {
        "title": "CVE-2009-4324",
        "what": "JavaScript calls media.newPlayer marker for CVE-2009-4324.",
        "why":  "Known Reader exploit fingerprint.",
        "family": "PDF JavaScript",
    },

    # ===== PDF: structure =====
    "PDF.ACROFORM": {
        "title": "Interactive form",
        "what": "PDF contains an AcroForm.",
        "why":  "Benign on its own. Combined with a SubmitForm action and a remote endpoint, it becomes a credential-harvesting form.",
        "family": "PDF structure",
    },
    "PDF.XFA": {
        "title": "XFA form",
        "what": "PDF contains XFA (XML Forms Architecture).",
        "why":  "XFA can carry its own scripts a separate code-execution surface from regular /JS.",
        "family": "PDF structure",
    },
    "PDF.XFA_SCRIPT": {
        "title": "XFA <script> block",
        "what": "An XFA form embeds a <script> element.",
        "why":  "Direct code in a form definition. Equivalent to a JS action.",
        "family": "PDF structure",
    },
    "PDF.EMBEDDED_FILE": {
        "title": "Embedded file",
        "what": "PDF contains an embedded file (any type).",
        "why":  "Could be a benign attachment or a staged payload inspect the file type.",
        "family": "PDF structure",
    },
    "PDF.EMBEDDED_FILE_PE": {
        "title": "Embedded Windows executable",
        "what": "PDF embeds a file whose first bytes are a PE/MZ header.",
        "why":  "Critical. There is no benign reason for a PDF to ship a .exe.",
        "family": "PDF structure",
    },
    "PDF.EMBEDDED_FILE_SCRIPT": {
        "title": "Embedded script/markup",
        "what": "PDF embeds a script or markup file.",
        "why":  "Stage for follow-on execution outside the PDF.",
        "family": "PDF structure",
    },
    "PDF.RICHMEDIA": {
        "title": "RichMedia annotation",
        "what": "Page has a /RichMedia annotation (legacy Flash/3D content).",
        "why":  "Rare in legitimate documents today legacy attack surface.",
        "family": "PDF structure",
    },

    # ===== PDF: streams =====
    "PDF.JBIG2DECODE": {
        "title": "/JBIG2Decode filter",
        "what": "A stream uses the JBIG2 decoder.",
        "why":  "Historically vulnerable (CVE-2009-0658); flagged for triage.",
        "family": "PDF streams",
    },
    "PDF.ASCII85_CHAINED": {
        "title": "Chained /ASCII85Decode",
        "what": "Stream is encoded with /ASCII85Decode applied 3+ times.",
        "why":  "No benign workflow does this obfuscation marker.",
        "family": "PDF streams",
    },
    "PDF.OBJSTM_HIDES_JS": {
        "title": "JS hidden in /ObjStm",
        "what": "An object stream contains /JS or /JavaScript references inside its compressed body.",
        "why":  "Classic evasion against scanners that don't decompress object streams.",
        "family": "PDF streams",
    },

    # ===== PDF: encryption =====
    "PDF.ENCRYPTED": {
        "title": "Encrypted PDF",
        "what": "PDF requires a password content cannot be analyzed inline.",
        "why":  "Often used to evade gateway scanners. Combined with a password hint in the email body, this is the classic phish.",
        "family": "PDF encryption",
    },
    "PDF.ENCRYPTED_WEAK_PASS": {
        "title": "Encrypted, weak password",
        "what": "PDF unlocks with a trivial password (empty, '1234', 'password', etc.).",
        "why":  "Weak encryption usually means it's there to defeat scanners, not protect content.",
        "family": "PDF encryption",
    },

    # ===== PDF: byte-level =====
    "PDF.POLYGLOT": {
        "title": "Polyglot file",
        "what": "File contains a non-trivial second format (PE/ZIP/etc.) before, after, or alongside the PDF.",
        "why":  "Polyglots are crafted to behave differently in different parsers a strong attack indicator.",
        "family": "PDF byte-level",
    },
    "PDF.SIZE_MISMATCH": {
        "title": "Object count mismatch",
        "what": "Trailer's /Size disagrees with the actual indirect-object count.",
        "why":  "Sometimes an evasion technique to hide objects from naive parsers.",
        "family": "PDF byte-level",
    },
    "PDF.MALFORMED": {
        "title": "Malformed PDF",
        "what": "Parser errored during walk file is corrupt or deliberately malformed.",
        "why":  "Broken files can still trigger reader bugs. Treat as suspicious.",
        "family": "PDF byte-level",
    },
    "PDF.IO_ERROR": {
        "title": "Read error",
        "what": "Could not read the PDF file from disk.",
        "why":  "Operational issue, not malicious content.",
        "family": "PDF byte-level",
    },
    "PDF.CLEAN": {
        "title": "Clean",
        "what": "No suspicious indicators detected.",
        "why":  "Default verdict when no rule fires.",
        "family": "Status",
    },

    # ===== Office: macros =====
    "OFFICE.VBA_PRESENT": {
        "title": "VBA macros present",
        "what": "Document contains a VBA project.",
        "why":  "Macros are the #1 enterprise malware delivery channel. Existence alone warrants caution.",
        "family": "Office macros",
    },
    "OFFICE.VBA_AUTOEXEC": {
        "title": "Auto-execute macro",
        "what": "VBA contains AutoOpen, Document_Open, Workbook_Open, Auto_Close, etc.",
        "why":  "These run as soon as the user opens the document. No click required.",
        "family": "Office macros",
    },
    "OFFICE.VBA_SUSPICIOUS": {
        "title": "Suspicious VBA keyword",
        "what": "VBA references an API category commonly used by malware.",
        "why":  "Worth review. Combined with autoexec and shell/download it becomes a confirmed dropper.",
        "family": "Office macros",
    },
    "OFFICE.VBA_SHELL": {
        "title": "VBA shell exec",
        "what": "VBA calls Shell, WScript.Shell, or CreateObject for shell execution.",
        "why":  "Spawns commands. Critical when paired with autoexec.",
        "family": "Office macros",
    },
    "OFFICE.VBA_DOWNLOAD": {
        "title": "VBA download",
        "what": "VBA uses URLDownloadToFile, MSXML2/WinHTTP/XMLHTTP to fetch a remote file.",
        "why":  "Classic stager. Critical when paired with autoexec or shell.",
        "family": "Office macros",
    },
    "OFFICE.VBA_OBFUSCATED": {
        "title": "Obfuscated VBA",
        "what": "Macro source uses Chr() / string concatenation in volume a hand-rolled obfuscator.",
        "why":  "Legitimate macros are not obfuscated. Strong suspicion marker.",
        "family": "Office macros",
    },
    "OFFICE.VBA_IOC_URL": {
        "title": "URL in VBA",
        "what": "Macro source contains a URL.",
        "why":  "Almost always the C2 / staging endpoint. Pivot from this URL.",
        "family": "Office macros",
    },
    "OFFICE.VBA_IOC_IP": {
        "title": "IP in VBA",
        "what": "Macro source contains a literal IP address.",
        "why":  "Direct C2 indicator IPs in macros are not coincidence.",
        "family": "Office macros",
    },
    "OFFICE.AUTOEXEC": {
        "title": "Document auto-exec",
        "what": "Document auto-executes some action on open (covers DDE, XLM, etc.).",
        "why":  "Generic auto-exec marker for correlations.",
        "family": "Office macros",
    },

    # ===== Office: OOXML =====
    "OFFICE.DDE": {
        "title": "DDE field code",
        "what": "Document.xml contains a DDE field-code structure.",
        "why":  "DDE is an old IPC mechanism abused for command exec. Even non-AUTO DDE fields can be wired to launch payloads.",
        "family": "OOXML structural",
    },
    "OFFICE.DDEAUTO": {
        "title": "DDEAUTO field code",
        "what": "Document defines a DDEAUTO field that runs without prompting.",
        "why":  "Fires the moment the user opens the doc common Office payload technique pre-2018.",
        "family": "OOXML structural",
    },
    "OFFICE.EXTERNAL_TEMPLATE": {
        "title": "External template injection",
        "what": "A relationship loads a remote attachedTemplate or oleObject over HTTP.",
        "why":  "CVE-2017-0199 family. The remote payload runs as soon as the doc opens.",
        "family": "OOXML structural",
    },
    "OFFICE.EXTERNAL_HTTP": {
        "title": "External HTTP target",
        "what": "Some relationship references an http(s) URL.",
        "why":  "Worth investigation not all are malicious, but it's a pivot point.",
        "family": "OOXML structural",
    },
    "OFFICE.EXTERNAL_REMOTE_IMG": {
        "title": "Remote image reference",
        "what": "Document loads an image from an external URL.",
        "why":  "Used for tracking pixels and NTLM-credential leaks via SMB/UNC.",
        "family": "OOXML structural",
    },
    "OFFICE.EMBEDDED_OLE": {
        "title": "Embedded OLE object",
        "what": "Document contains an embedded oleObject*.bin.",
        "why":  "Inspect the embedded file may be a benign chart or a payload dropper.",
        "family": "OOXML structural",
    },
    "OFFICE.EMBEDDED_OLE_PE": {
        "title": "Embedded PE in OLE",
        "what": "Embedded OLE object's bytes start with an MZ/PE header.",
        "why":  "Critical the document literally ships a Windows executable.",
        "family": "OOXML structural",
    },

    # ===== Office: RTF =====
    "OFFICE.RTF_OLE_EQUATION": {
        "title": "RTF Equation.3 OLE",
        "what": "RTF embeds an Equation.3/Equation.2 OLE object.",
        "why":  "CVE-2017-11882 / CVE-2018-0802 abused Equation Editor for years.",
        "family": "RTF",
    },
    "OFFICE.RTF_OLE_LINK": {
        "title": "RTF OLE2Link",
        "what": "RTF embeds an OLE2Link object.",
        "why":  "CVE-2017-0199 marker fetches a remote payload on open.",
        "family": "RTF",
    },
    "OFFICE.RTF_OLE_PACKAGE": {
        "title": "RTF Package object",
        "what": "RTF embeds a Package OLE object (file-drop wrapper).",
        "why":  "Drops an arbitrary file (often a script) when activated.",
        "family": "RTF",
    },
    "OFFICE.RTF_OLE_PACKAGE_PE": {
        "title": "RTF Package contains PE",
        "what": "RTF Package object payload starts with an MZ/PE header.",
        "why":  "Critical RTF carries a Windows executable.",
        "family": "RTF",
    },

    # ===== Office: XLM =====
    "OFFICE.XLM_MACROS": {
        "title": "Excel 4.0 (XLM) macros",
        "what": "Document contains legacy Excel 4.0 macros.",
        "why":  "XLM bypasses many VBA-only scanners; popular 2020-2022.",
        "family": "Office macros",
    },
    "OFFICE.XLM_AUTOEXEC": {
        "title": "XLM auto_open",
        "what": "An auto_open / auto_close XLM macro is defined.",
        "why":  "Auto-runs on open without prompting.",
        "family": "Office macros",
    },

    # ===== Office: encryption =====
    "OFFICE.ENCRYPTED": {
        "title": "Encrypted Office doc",
        "what": "Document is password-protected and content cannot be analyzed inline.",
        "why":  "Used to evade gateway scanners. Combined with a password hint in the email body, classic phish pattern.",
        "family": "Office encryption",
    },
    "OFFICE.ENCRYPTED_WEAK_PASS": {
        "title": "Encrypted, weak password",
        "what": "Document unlocks with a trivial password (empty, '1234', 'VelvetSweatshop', etc.).",
        "why":  "Trivial password = anti-scanner protection, not real protection.",
        "family": "Office encryption",
    },

    # ===== Office: errors / status =====
    "OFFICE.MALFORMED": {
        "title": "Malformed document",
        "what": "Parser errored during analysis the file is corrupt or deliberately malformed.",
        "why":  "Broken Office files can still trigger reader bugs.",
        "family": "Office status",
    },
    "OFFICE.CLEAN": {
        "title": "Clean",
        "what": "No suspicious indicators detected.",
        "why":  "Default verdict when no rule fires.",
        "family": "Status",
    },

    # ===== Email-level =====
    "EMAIL.PASSWORD_HINT": {
        "title": "Password hint in body",
        "what": "Email body contains a phrase like 'password is X'.",
        "why":  "When paired with an encrypted attachment, this is textbook phish.",
        "family": "Email signal",
    },

    # ===== Setup / operational =====
    "SETUP.PIKEPDF_MISSING": {
        "title": "pikepdf not installed",
        "what": "PDF analysis library is not available.",
        "why":  "Install with pip install pikepdf.",
        "family": "Operational",
    },
    "SETUP.OLETOOLS_MISSING": {
        "title": "oletools not installed",
        "what": "Office analysis library is not available.",
        "why":  "Install with pip install oletools.",
        "family": "Operational",
    },
}


# Friendly description per analyzer/tool name (used by the legend section).
TOOL_CATALOG: Dict[str, Dict[str, str]] = {
    "pikepdf": {
        "title": "pikepdf",
        "what": "Native Python bindings to libqpdf. Walks the PDF object graph, "
                "decompresses streams, resolves indirect references, opens "
                "encrypted documents.",
        "why":  "Replaces the old subprocess calls to pdf-parser.py. Far faster "
                "and produces structured findings instead of stdout text.",
    },
    "byte-scan-fallback": {
        "title": "PDF byte-scan fallback",
        "what": "Pure-bytes scan of a PDF when pikepdf cannot open it. Looks "
                "for marker strings like /JS, /Launch, /OpenAction.",
        "why":  "Broken PDFs are themselves suspicious we want findings even "
                "when the structured parser fails.",
    },
    "VBA_Parser": {
        "title": "oletools VBA_Parser",
        "what": "Extracts every VBA macro module from OLE2/OOXML, runs autoexec / "
                "suspicious / pattern detectors, and reveals deobfuscated source.",
        "why":  "Replaces the old subprocess call to olevba.py. Gives us "
                "structured Python objects we can iterate over instead of "
                "scraping stdout.",
    },
    "OleID": {
        "title": "oletools OleID",
        "what": "Identifies OLE2 documents and surfaces high-level indicators "
                "(macros present, flash present, external relationships).",
        "why":  "Replaces the old subprocess call to oleid.py.",
    },
    "olefile": {
        "title": "olefile",
        "what": "Low-level OLE2 stream reader. Lists streams, lets us read raw "
                "macro storage if needed.",
        "why":  "Underpins the OLE2 dispatch path.",
    },
    "rtfobj": {
        "title": "oletools rtfobj",
        "what": "Parses RTF documents, extracts embedded OLE objects, identifies "
                "their class names (Equation.3, OLE2Link, Package).",
        "why":  "Catches CVE-2017-11882 / CVE-2017-0199 family payloads.",
    },
    "msoffcrypto": {
        "title": "msoffcrypto-tool",
        "what": "Detects encrypted Office documents and decrypts them with "
                "common/weak passwords (including hints harvested from the "
                "email body).",
        "why":  "Encrypted-then-shipped is a classic anti-scanner phish pattern.",
    },
    "ooxml-zip": {
        "title": "OOXML zip walker",
        "what": "Treats .docx/.xlsx/.pptx as the zip containers they are. "
                "Parses _rels XML safely (defusedxml), inspects every part "
                "for DDE field codes, embedded OLE, external templates.",
        "why":  "DDE / external template / embedded PE drops are OOXML-only "
                "indicators that the legacy stdout-scraping pipeline missed.",
    },
}


def code_info(code: str) -> CodeInfo:
    """Return catalog entry for a code, or a stub if unknown."""
    info = CODE_CATALOG.get(code)
    if info is not None:
        return info
    # Unknown code best-effort stub from the prefix
    family = "Other"
    if code.startswith("PDF."):
        family = "PDF (other)"
    elif code.startswith("OFFICE."):
        family = "Office (other)"
    elif code.startswith("EMAIL."):
        family = "Email"
    elif code.startswith("SETUP."):
        family = "Operational"
    return {
        "title": code.replace(".", " · ").replace("_", " ").title(),
        "what":  "(no description registered for this code)",
        "why":   "",
        "family": family,
    }


def families() -> Dict[str, list]:
    """Return codes grouped by family for the legend section."""
    out: Dict[str, list] = {}
    for code, info in CODE_CATALOG.items():
        fam = info.get("family", "Other")
        out.setdefault(fam, []).append(code)
    for fam in out:
        out[fam].sort()
    return out
