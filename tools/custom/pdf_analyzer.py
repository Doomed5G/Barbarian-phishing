#!/usr/bin/env python3
"""
PDF analyzer replaces the pdf-parser.py subprocess pipeline.

Walks the PDF object graph with pikepdf (libqpdf), decompresses streams,
resolves indirect references, and emits structured findings with stable
codes consumed by tools.custom.scoring.ScoreEngine.

Falls back to a byte-level scan when pikepdf cannot open the file (a
broken PDF is itself suspicious we still want findings).
"""

import hashlib
import io
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Optional third-party imports -- degrade gracefully when missing
# ---------------------------------------------------------------------------
try:
    import pikepdf
    HAS_PIKEPDF = True
except ImportError:
    HAS_PIKEPDF = False

try:
    from defusedxml import ElementTree as DefusedET
    HAS_DEFUSEDXML = True
except ImportError:
    HAS_DEFUSEDXML = False

from .iocs import IOCExtractor
from .scoring import ScoreEngine


# ---------------------------------------------------------------------------
# Action subtype -> finding code + base severity
# ---------------------------------------------------------------------------
_ACTION_SUBTYPE_MAP: Dict[str, Tuple[str, str, str]] = {
    # /S name        : (finding code,                 severity, category)
    "/JavaScript":     ("PDF.ACTION_JAVASCRIPT",      "HIGH",     "JavaScript Action"),
    "/Launch":         ("PDF.ACTION_LAUNCH",          "CRITICAL", "Launch Action"),
    "/SubmitForm":     ("PDF.ACTION_SUBMITFORM",      "HIGH",     "SubmitForm Action"),
    "/ImportData":     ("PDF.ACTION_IMPORTDATA",      "HIGH",     "ImportData Action"),
    "/GoToR":          ("PDF.ACTION_GOTOR",           "MEDIUM",   "Remote GoTo"),
    "/GoToE":          ("PDF.ACTION_GOTOE",           "MEDIUM",   "Embedded GoTo"),
    "/URI":            ("PDF.ACTION_URI",             "LOW",      "URI Action"),
    "/Named":          ("PDF.ACTION_NAMED",           "LOW",      "Named Action"),
    "/Hide":           ("PDF.ACTION_HIDE",            "LOW",      "Hide Action"),
    "/RichMediaExecute": ("PDF.ACTION_RICHMEDIAEXECUTE", "HIGH",  "RichMediaExecute Action"),
}

# JavaScript content scanners pattern -> (code, severity, message)
_JS_PATTERNS: List[Tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"\beval\s*\("),                   "PDF.JS_EVAL",       "HIGH",     "eval() in PDF JavaScript"),
    (re.compile(r"\bunescape\s*\("),               "PDF.JS_UNESCAPE",   "MEDIUM",   "unescape() in PDF JavaScript (obfuscation marker)"),
    (re.compile(r"String\.fromCharCode\s*\("),     "PDF.JS_FROMCHARCODE","MEDIUM",  "String.fromCharCode() in PDF JavaScript (obfuscation marker)"),
    (re.compile(r"app\.launchURL\s*\("),           "PDF.JS_LAUNCH_URL", "HIGH",     "app.launchURL() in PDF JavaScript"),
    (re.compile(r"util\.printf\s*\("),             "PDF.JS_UTIL_PRINTF","HIGH",     "util.printf() in PDF JavaScript (CVE-2008-2992 marker)"),
    (re.compile(r"Collab\.collectEmailInfo\s*\("), "PDF.JS_CVE_COLLAB_EMAIL",   "CRITICAL", "Collab.collectEmailInfo (CVE-2007-5659)"),
    (re.compile(r"Collab\.getIcon\s*\("),          "PDF.JS_CVE_COLLAB_GETICON", "CRITICAL", "Collab.getIcon (CVE-2009-0927)"),
    (re.compile(r"\bgetAnnots\s*\("),              "PDF.JS_CVE_GETANNOTS",      "CRITICAL", "getAnnots (CVE-2009-1492)"),
    (re.compile(r"media\.newPlayer\s*\("),         "PDF.JS_CVE_NEWPLAYER",      "CRITICAL", "media.newPlayer (CVE-2009-4324)"),
    (re.compile(r"(?:%u[0-9a-fA-F]{4}){4,}|(?:\\x[0-9a-fA-F]{2}){8,}"),
                                                    "PDF.JS_SHELLCODE",  "CRITICAL", "Shellcode-style hex/unicode escapes"),
]

# How many of the same JS pattern hits before we collapse them
_JS_LONG_LITERAL_THRESHOLD = 200
_PDF_HEADER = b"%PDF-"
_PDF_EOF = b"%%EOF"
_PE_MAGIC = b"MZ"
_ZIP_MAGIC = b"PK\x03\x04"

# Common owner/user passwords to try on encrypted PDFs
_PDF_PASSWORD_GUESSES = ["", "1234", "12345", "123456", "password", "VelvetSweatshop"]


class PDFAnalyzer:
    """Replaces analyze_pdf / analyze_pdf_direct in barbarian-phishing.py."""

    def __init__(
        self,
        ioc_extractor: Optional[IOCExtractor] = None,
        score_engine: Optional[ScoreEngine] = None,
    ):
        self.iocs = ioc_extractor or IOCExtractor()
        self.scorer = score_engine or ScoreEngine()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, filepath: Path, email_body: str = "") -> Dict[str, Any]:
        """Analyze a PDF. ``email_body`` is optional if supplied, we'll
        harvest password candidates from it for encrypted-PDF unlock."""
        filepath = Path(filepath)
        result = self._base_result(filepath)

        if not HAS_PIKEPDF:
            result["findings"].append({
                "severity": "WARNING",
                "category": "Setup",
                "message": "pikepdf not installed install with `pip install pikepdf`",
                "code": "SETUP.PIKEPDF_MISSING",
            })
            self._track_tool(result, "pikepdf", "unavailable")
            self._fallback_byte_scan(filepath, result)
            self._finalize(result)
            return result

        raw_bytes = self._read_raw(filepath, result)
        if raw_bytes is None:
            self._finalize(result)
            return result

        # Byte-level checks always run (cheap, work even when pikepdf fails)
        self._check_polyglot(raw_bytes, result)

        pdf, encrypted_finding = self._open_with_password_attempts(
            filepath, email_body, result,
        )
        if encrypted_finding is not None:
            result["findings"].append(encrypted_finding)

        if pdf is None:
            self._track_tool(result, "pikepdf", "error",
                             error="Could not open PDF (corrupt or strongly encrypted)")
            self._fallback_byte_scan(filepath, result, raw_bytes=raw_bytes)
            self._finalize(result)
            return result

        try:
            self._walk_pdf(pdf, result)
        except Exception as e:  # noqa: BLE001 analyzer must not crash main script
            result["findings"].append({
                "severity": "WARNING",
                "category": "Analyzer Error",
                "message": f"Object walk raised: {type(e).__name__}: {e}",
                "code": "PDF.MALFORMED",
                "details": str(e)[:300],
            })
        finally:
            try:
                pdf.close()
            except Exception:
                pass

        self._track_tool(result, "pikepdf", "success", type_="primary")
        self._finalize(result)
        return result

    # ------------------------------------------------------------------
    # Skeleton helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _base_result(filepath: Path) -> Dict[str, Any]:
        return {
            "file": str(filepath),
            "type": "PDF",
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "tools_used": [],
            "iocs": {},
            "statistics": {},
        }

    @staticmethod
    def _track_tool(result: Dict, name: str, status: str,
                    type_: str = "primary", error: str = "") -> None:
        entry = {
            "name": name,
            "status": status,
            "type": type_,
            "timestamp": datetime.now().isoformat(),
        }
        if error:
            entry["error"] = error
        result["tools_used"].append(entry)

    @staticmethod
    def _read_raw(filepath: Path, result: Dict) -> Optional[bytes]:
        try:
            return filepath.read_bytes()
        except OSError as e:
            result["findings"].append({
                "severity": "ERROR",
                "category": "I/O",
                "message": f"Could not read file: {e}",
                "code": "PDF.IO_ERROR",
            })
            return None

    # ------------------------------------------------------------------
    # Open + encryption handling
    # ------------------------------------------------------------------

    def _open_with_password_attempts(
        self,
        filepath: Path,
        email_body: str,
        result: Dict,
    ) -> Tuple[Optional["pikepdf.Pdf"], Optional[Dict]]:
        """Returns (pdf-or-None, optional encryption finding)."""
        encryption_finding: Optional[Dict] = None
        try:
            return pikepdf.open(str(filepath)), None
        except pikepdf.PasswordError:
            pass
        except pikepdf.PdfError as e:
            result["findings"].append({
                "severity": "MEDIUM",
                "category": "Malformed PDF",
                "message": f"PDF structure error: {e}",
                "code": "PDF.MALFORMED",
                "details": str(e)[:300],
                "confidence": 0.7,
            })
            return None, None

        # Encrypted try guesses
        guesses = list(_PDF_PASSWORD_GUESSES)
        guesses.extend(self._password_candidates_from_body(email_body))
        for pwd in guesses:
            try:
                pdf = pikepdf.open(str(filepath), password=pwd)
                encryption_finding = {
                    "severity": "HIGH",
                    "category": "Encrypted PDF",
                    "message": (
                        f"PDF is password-protected and unlocks with the trivial "
                        f"password '{pwd}'." if pwd else
                        "PDF is encrypted with an empty user password "
                        "(owner-password protection is bypass-only)."
                    ),
                    "code": "PDF.ENCRYPTED_WEAK_PASS",
                    "evidence": {"excerpt": f"password={pwd!r}"},
                    "confidence": 0.95,
                }
                return pdf, encryption_finding
            except pikepdf.PasswordError:
                continue
            except pikepdf.PdfError:
                break

        # Couldn't unlock with any guess
        encryption_finding = {
            "severity": "MEDIUM",
            "category": "Encrypted PDF",
            "message": "PDF is password-protected content not analyzable inline.",
            "code": "PDF.ENCRYPTED",
            "confidence": 0.9,
        }
        return None, encryption_finding

    @staticmethod
    def _password_candidates_from_body(text: str) -> List[str]:
        if not text:
            return []
        out: List[str] = []
        for m in re.finditer(
            r"(?i)password\s*(?:is|=|:)\s*[\"']?([^\s\"'\.,;]{1,32})",
            text,
        ):
            out.append(m.group(1))
        return out

    # ------------------------------------------------------------------
    # Object graph walk
    # ------------------------------------------------------------------

    def _walk_pdf(self, pdf: "pikepdf.Pdf", result: Dict) -> None:
        stats = self._compute_stats(pdf)
        result["statistics"].update(stats)

        seen_codes: Set[str] = set()
        ioc_buckets: List[Dict[str, List[str]]] = []

        # Catalog-level triggers
        root = pdf.Root
        self._inspect_catalog_triggers(root, result, seen_codes, ioc_buckets, pdf)

        # AcroForm + XFA
        self._inspect_acroform(root, result, seen_codes, ioc_buckets)

        # Embedded files
        self._inspect_embedded_files(root, result, seen_codes, ioc_buckets)

        # Page-level: annotations and per-page additional actions
        self._inspect_pages(pdf, result, seen_codes, ioc_buckets)

        # Object-level pass actions + JS bodies + filter audit + ObjStm
        for obj in pdf.objects:
            try:
                self._inspect_object(obj, result, seen_codes, ioc_buckets)
            except Exception:
                # Don't let one weird object kill the rest of the walk
                continue

        result["iocs"] = IOCExtractor.union(*ioc_buckets) if ioc_buckets else {}

    @staticmethod
    def _compute_stats(pdf: "pikepdf.Pdf") -> Dict[str, Any]:
        stats: Dict[str, Any] = {}
        try:
            stats["page_count"] = len(pdf.pages)
        except Exception:
            stats["page_count"] = None
        try:
            stats["object_count"] = sum(1 for _ in pdf.objects)
        except Exception:
            stats["object_count"] = None
        try:
            stats["pdf_version"] = pdf.pdf_version
        except Exception:
            pass
        try:
            stats["is_encrypted"] = bool(pdf.is_encrypted)
        except Exception:
            pass
        return stats

    # ---------- catalog triggers ----------

    def _inspect_catalog_triggers(
        self,
        root: Any,
        result: Dict,
        seen_codes: Set[str],
        ioc_buckets: List[Dict[str, List[str]]],
        pdf: "pikepdf.Pdf",
    ) -> None:
        # /OpenAction
        oa = self._safe_get(root, "/OpenAction")
        if oa is not None:
            self._add(result, seen_codes, {
                "severity": "HIGH",
                "category": "OpenAction Trigger",
                "message": "PDF auto-runs an action when opened (/OpenAction).",
                "code": "PDF.OPENACTION",
                "evidence": self._evidence_for(oa),
                "confidence": 0.95,
                "mitre_attack": ["T1204.002"],
            })
            self._inspect_action_target(oa, result, seen_codes, ioc_buckets,
                                        trigger="/OpenAction")

        # /AA on catalog
        aa = self._safe_get(root, "/AA")
        if aa is not None:
            self._add(result, seen_codes, {
                "severity": "HIGH",
                "category": "Additional Actions",
                "message": "PDF defines /AA additional-action triggers on the catalog.",
                "code": "PDF.AUTOACTION",
                "evidence": self._evidence_for(aa),
                "confidence": 0.85,
                "mitre_attack": ["T1204.002"],
            })

        # Per-page /AA
        try:
            for i, page in enumerate(pdf.pages):
                page_aa = self._safe_get(page.obj, "/AA") if hasattr(page, "obj") else None
                if page_aa is None:
                    page_aa = self._safe_get(page, "/AA")
                if page_aa is not None and "PDF.AUTOACTION" not in seen_codes:
                    self._add(result, seen_codes, {
                        "severity": "HIGH",
                        "category": "Page Additional Actions",
                        "message": f"PDF page {i + 1} defines /AA additional-action triggers.",
                        "code": "PDF.AUTOACTION",
                        "evidence": self._evidence_for(page_aa),
                        "confidence": 0.85,
                    })
                    break
        except Exception:
            pass

    def _inspect_action_target(
        self,
        action: Any,
        result: Dict,
        seen_codes: Set[str],
        ioc_buckets: List[Dict[str, List[str]]],
        trigger: str,
    ) -> None:
        """Resolve an action object's /S subtype and emit a finding."""
        subtype = self._safe_get_name(action, "/S")
        if subtype is None:
            return
        mapping = _ACTION_SUBTYPE_MAP.get(subtype)
        if mapping is None:
            return
        code, sev, category = mapping
        msg = f"{category} reachable via {trigger}."
        evidence = self._evidence_for(action)
        self._add(result, seen_codes, {
            "severity": sev,
            "category": category,
            "message": msg,
            "code": code,
            "evidence": evidence,
            "confidence": 0.9,
            "mitre_attack": ["T1204.002"] if "JavaScript" in subtype or "Launch" in subtype else [],
        })
        # If JS, scan body
        if subtype == "/JavaScript":
            self._scan_js_body(action, result, seen_codes, ioc_buckets)
        # If URI, harvest URL
        if subtype == "/URI":
            uri = self._safe_get_string(action, "/URI")
            if uri:
                ioc_buckets.append({"urls": [uri]})

    # ---------- per-object pass ----------

    def _inspect_object(
        self,
        obj: Any,
        result: Dict,
        seen_codes: Set[str],
        ioc_buckets: List[Dict[str, List[str]]],
    ) -> None:
        # Action object?
        if self._is_dict_like(obj):
            type_ = self._safe_get_name(obj, "/Type")
            subtype = self._safe_get_name(obj, "/S")
            if type_ == "/Action" or subtype in _ACTION_SUBTYPE_MAP:
                self._inspect_action_target(obj, result, seen_codes, ioc_buckets,
                                            trigger="object reference")

        # Stream filter audit
        if self._is_stream(obj):
            self._inspect_stream_filters(obj, result, seen_codes)

    def _inspect_stream_filters(
        self,
        stream: Any,
        result: Dict,
        seen_codes: Set[str],
    ) -> None:
        try:
            filt = stream.get("/Filter")
        except Exception:
            filt = None
        names = self._normalize_filter(filt) if filt is not None else []

        if "/JBIG2Decode" in names:
            self._add(result, seen_codes, {
                "severity": "MEDIUM",
                "category": "Suspicious Filter",
                "message": "Stream uses /JBIG2Decode (CVE-2009-0658 family).",
                "code": "PDF.JBIG2DECODE",
                "evidence": self._evidence_for(stream),
                "confidence": 0.7,
            })

        if names.count("/ASCII85Decode") >= 3:
            self._add(result, seen_codes, {
                "severity": "MEDIUM",
                "category": "Suspicious Filter",
                "message": "Stream chains /ASCII85Decode 3+ times (obfuscation).",
                "code": "PDF.ASCII85_CHAINED",
                "evidence": self._evidence_for(stream),
                "confidence": 0.7,
            })

        # Inspect ObjStm regardless of /Filter pikepdf may auto-decode it
        if "/ObjStm" in names or self._safe_get_name(stream, "/Type") == "/ObjStm":
            try:
                data = stream.read_bytes()
            except Exception:
                try:
                    data = stream.read_raw_bytes()
                except Exception:
                    data = b""
            if b"/JS" in data or b"/JavaScript" in data:
                self._add(result, seen_codes, {
                    "severity": "HIGH",
                    "category": "Hidden JavaScript",
                    "message": "Object stream (/ObjStm) hides /JS or /JavaScript references.",
                    "code": "PDF.OBJSTM_HIDES_JS",
                    "evidence": self._evidence_for(stream),
                    "confidence": 0.85,
                })

    @staticmethod
    def _normalize_filter(filt: Any) -> List[str]:
        try:
            # Could be a Name or an Array of Names
            if hasattr(filt, "__iter__") and not isinstance(filt, (str, bytes)):
                return [str(f) for f in filt]
            return [str(filt)]
        except Exception:
            return []

    # ---------- AcroForm / XFA ----------

    def _inspect_acroform(
        self,
        root: Any,
        result: Dict,
        seen_codes: Set[str],
        ioc_buckets: List[Dict[str, List[str]]],
    ) -> None:
        af = self._safe_get(root, "/AcroForm")
        if af is None:
            return
        self._add(result, seen_codes, {
            "severity": "INFO",
            "category": "AcroForm",
            "message": "PDF contains an interactive AcroForm.",
            "code": "PDF.ACROFORM",
            "confidence": 1.0,
        })
        xfa = self._safe_get(af, "/XFA")
        if xfa is None:
            return
        self._add(result, seen_codes, {
            "severity": "MEDIUM",
            "category": "XFA Form",
            "message": "PDF contains an XFA (XML Forms) definition.",
            "code": "PDF.XFA",
            "confidence": 1.0,
        })

        # XFA can be an array of (name, stream) pairs or a single stream
        xfa_xml = self._concat_xfa_xml(xfa)
        if not xfa_xml:
            return
        scripts = self._extract_xfa_scripts(xfa_xml)
        for src in scripts:
            self._add(result, seen_codes, {
                "severity": "HIGH",
                "category": "XFA Script",
                "message": "XFA form embeds a <script> block.",
                "code": "PDF.XFA_SCRIPT",
                "evidence": {"excerpt": src[:200]},
                "confidence": 0.9,
                "mitre_attack": ["T1204.002"],
            })
            ioc_buckets.append(self.iocs.extract(src))

    def _concat_xfa_xml(self, xfa: Any) -> str:
        chunks: List[bytes] = []
        try:
            if hasattr(xfa, "__iter__") and not self._is_dict_like(xfa) and not self._is_stream(xfa):
                # Array form: alternating name, stream
                items = list(xfa)
                for it in items:
                    if self._is_stream(it):
                        try:
                            chunks.append(it.read_bytes())
                        except Exception:
                            pass
            elif self._is_stream(xfa):
                try:
                    chunks.append(xfa.read_bytes())
                except Exception:
                    pass
        except Exception:
            pass
        return b"\n".join(chunks).decode("utf-8", errors="ignore")

    @staticmethod
    def _extract_xfa_scripts(xml_text: str) -> List[str]:
        if not xml_text:
            return []
        if HAS_DEFUSEDXML:
            try:
                root = DefusedET.fromstring(xml_text)
                return [
                    (el.text or "")
                    for el in root.iter()
                    if el.tag.lower().endswith("script") and (el.text or "").strip()
                ]
            except Exception:
                pass
        # Regex fallback
        return [
            m.group(1)
            for m in re.finditer(r"(?is)<script[^>]*>(.*?)</script>", xml_text)
            if m.group(1).strip()
        ]

    # ---------- Embedded files ----------

    def _inspect_embedded_files(
        self,
        root: Any,
        result: Dict,
        seen_codes: Set[str],
        ioc_buckets: List[Dict[str, List[str]]],
    ) -> None:
        names = self._safe_get(root, "/Names")
        if names is None:
            return
        ef_tree = self._safe_get(names, "/EmbeddedFiles")
        if ef_tree is None:
            return
        for filename, stream in self._walk_name_tree(ef_tree):
            self._handle_embedded_file(filename, stream, result, seen_codes,
                                        ioc_buckets)

    def _walk_name_tree(self, node: Any):
        try:
            kids = node.get("/Kids")
            if kids is not None:
                for kid in kids:
                    yield from self._walk_name_tree(kid)
                return
            entries = node.get("/Names")
            if entries is None:
                return
            entries = list(entries)
            # Names array: alternating filename, file-spec dict
            for i in range(0, len(entries), 2):
                if i + 1 >= len(entries):
                    break
                name = str(entries[i])
                spec = entries[i + 1]
                ef_dict = self._safe_get(spec, "/EF")
                if ef_dict is None:
                    yield name, None
                    continue
                stream = self._safe_get(ef_dict, "/F") or self._safe_get(ef_dict, "/UF")
                yield name, stream
        except Exception:
            return

    def _handle_embedded_file(
        self,
        filename: str,
        stream: Any,
        result: Dict,
        seen_codes: Set[str],
        ioc_buckets: List[Dict[str, List[str]]],
    ) -> None:
        if stream is None or not self._is_stream(stream):
            self._add(result, seen_codes, {
                "severity": "INFO",
                "category": "Embedded File",
                "message": f"PDF contains embedded file reference: {filename}",
                "code": "PDF.EMBEDDED_FILE",
                "evidence": {"excerpt": filename},
                "confidence": 0.9,
            })
            return
        try:
            data = stream.read_bytes()
        except Exception:
            data = b""
        head = data[:4]
        sha256 = hashlib.sha256(data).hexdigest() if data else None

        if head == b"MZ" or head[:2] == _PE_MAGIC:
            self._add(result, seen_codes, {
                "severity": "CRITICAL",
                "category": "Embedded Executable",
                "message": f"PDF embeds a Windows PE executable: {filename}",
                "code": "PDF.EMBEDDED_FILE_PE",
                "evidence": {"excerpt": filename, "offset": 0},
                "iocs": {"hashes_sha256": [sha256] if sha256 else []},
                "confidence": 1.0,
                "mitre_attack": ["T1027.009", "T1204.002"],
            })
            return

        if (data[:2] == b"#!" or
                head in (b"<scr", b"<htm") or
                data[:5].lower() == b"<?xml"):
            self._add(result, seen_codes, {
                "severity": "HIGH",
                "category": "Embedded Script",
                "message": f"PDF embeds a script/markup file: {filename}",
                "code": "PDF.EMBEDDED_FILE_SCRIPT",
                "evidence": {"excerpt": filename},
                "iocs": {"hashes_sha256": [sha256] if sha256 else []},
                "confidence": 0.9,
            })
            return

        self._add(result, seen_codes, {
            "severity": "MEDIUM",
            "category": "Embedded File",
            "message": f"PDF embeds a file: {filename} ({len(data)} bytes)",
            "code": "PDF.EMBEDDED_FILE",
            "evidence": {"excerpt": filename},
            "iocs": {"hashes_sha256": [sha256] if sha256 else []},
            "confidence": 0.8,
        })

    # ---------- Page-level annotations ----------

    def _inspect_pages(
        self,
        pdf: "pikepdf.Pdf",
        result: Dict,
        seen_codes: Set[str],
        ioc_buckets: List[Dict[str, List[str]]],
    ) -> None:
        try:
            pages = list(pdf.pages)
        except Exception:
            return
        for page_idx, page in enumerate(pages):
            try:
                annots = page.get("/Annots")
            except Exception:
                annots = None
            if annots is None:
                continue
            try:
                annots = list(annots)
            except TypeError:
                continue

            for annot in annots:
                self._inspect_annotation(annot, page_idx, result, seen_codes, ioc_buckets)

    def _inspect_annotation(
        self,
        annot: Any,
        page_idx: int,
        result: Dict,
        seen_codes: Set[str],
        ioc_buckets: List[Dict[str, List[str]]],
    ) -> None:
        if not self._is_dict_like(annot):
            return

        # /Subtype = /RichMedia annotation
        subtype = self._safe_get_name(annot, "/Subtype")
        if subtype == "/RichMedia":
            self._add(result, seen_codes, {
                "severity": "HIGH",
                "category": "RichMedia Annotation",
                "message": f"Page {page_idx + 1} has a /RichMedia annotation "
                           f"(Flash/3D content embedded in PDF).",
                "code": "PDF.RICHMEDIA",
                "evidence": self._evidence_for(annot),
                "confidence": 0.9,
            })

        # /A = action triggered on the annotation (e.g. click)
        action = self._safe_get(annot, "/A")
        if action is not None:
            self._inspect_action_target(
                action, result, seen_codes, ioc_buckets,
                trigger=f"page {page_idx + 1} annotation /A",
            )

        # /AA = additional actions on the annotation
        aa = self._safe_get(annot, "/AA")
        if aa is not None and self._is_dict_like(aa):
            self._add(result, seen_codes, {
                "severity": "MEDIUM",
                "category": "Annotation Additional Actions",
                "message": f"Page {page_idx + 1} annotation defines /AA triggers.",
                "code": "PDF.AUTOACTION",
                "evidence": self._evidence_for(aa),
                "confidence": 0.8,
            })
            # Inspect each AA child action
            try:
                for k in aa.keys():
                    child = self._safe_get(aa, k)
                    if child is not None:
                        self._inspect_action_target(
                            child, result, seen_codes, ioc_buckets,
                            trigger=f"page {page_idx + 1} annotation /AA/{k}",
                        )
            except Exception:
                pass

    # ---------- JavaScript body scan ----------

    def _scan_js_body(
        self,
        action: Any,
        result: Dict,
        seen_codes: Set[str],
        ioc_buckets: List[Dict[str, List[str]]],
    ) -> None:
        js = self._safe_get(action, "/JS")
        if js is None:
            return
        js_text = self._js_to_text(js)
        if not js_text:
            return
        # Run deobfuscation; original text retained inside deobf
        deobf = self.iocs.deobfuscate_string(js_text)

        # Long literal heuristic
        if any(len(s) >= _JS_LONG_LITERAL_THRESHOLD
               for s in re.findall(r'"[^"\n]+"', js_text)):
            self._add(result, seen_codes, {
                "severity": "MEDIUM",
                "category": "JavaScript Obfuscation",
                "message": (
                    f"PDF JavaScript contains a string literal "
                    f">= {_JS_LONG_LITERAL_THRESHOLD} chars (obfuscation marker)."
                ),
                "code": "PDF.JS_LONG_LITERAL",
                "evidence": {"excerpt": js_text[:200]},
                "confidence": 0.6,
            })

        for pat, code, sev, msg in _JS_PATTERNS:
            if pat.search(deobf):
                m = pat.search(deobf)
                self._add(result, seen_codes, {
                    "severity": sev,
                    "category": "JavaScript Code",
                    "message": msg,
                    "code": code,
                    "evidence": {
                        "excerpt": deobf[max(0, m.start() - 40): m.end() + 40][:200],
                    },
                    "confidence": 0.85,
                    "mitre_attack": ["T1059.007"],
                })

        ioc_buckets.append(self.iocs.extract(deobf))

    @staticmethod
    def _js_to_text(js: Any) -> str:
        try:
            if hasattr(js, "read_bytes"):
                return js.read_bytes().decode("utf-8", errors="ignore")
            return str(js)
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Byte-level checks
    # ------------------------------------------------------------------

    def _check_polyglot(self, raw: bytes, result: Dict) -> None:
        seen_codes: Set[str] = {f.get("code") for f in result["findings"] if f.get("code")}
        # %PDF- not at offset 0 (or first 1024)
        first_pdf = raw.find(_PDF_HEADER)
        if first_pdf > 1024:
            self._add(result, seen_codes, {
                "severity": "HIGH",
                "category": "Polyglot",
                "message": (
                    f"%PDF- header found at offset {first_pdf} file likely a polyglot."
                ),
                "code": "PDF.POLYGLOT",
                "evidence": {"offset": first_pdf, "excerpt": raw[:64].hex()},
                "confidence": 0.85,
            })

        # Multiple %PDF- occurrences
        if first_pdf >= 0 and raw.count(_PDF_HEADER) > 1:
            self._add(result, seen_codes, {
                "severity": "MEDIUM",
                "category": "Polyglot",
                "message": "Multiple %PDF- headers possible appended-PDF polyglot.",
                "code": "PDF.POLYGLOT",
                "confidence": 0.7,
            })

        # Trailing bytes after last %%EOF
        last_eof = raw.rfind(_PDF_EOF)
        if last_eof != -1:
            tail = raw[last_eof + len(_PDF_EOF):]
            tail_stripped = tail.strip()
            # tolerate small whitespace
            if len(tail_stripped) > 8:
                if tail_stripped.startswith(_PE_MAGIC) or tail_stripped.startswith(_ZIP_MAGIC):
                    self._add(result, seen_codes, {
                        "severity": "HIGH",
                        "category": "Polyglot",
                        "message": (
                            f"Non-trivial data ({len(tail_stripped)} bytes) after %%EOF "
                            f"begins with {tail_stripped[:4]!r}"
                        ),
                        "code": "PDF.POLYGLOT",
                        "evidence": {"offset": last_eof + len(_PDF_EOF)},
                        "confidence": 0.95,
                    })

    def _fallback_byte_scan(self, filepath: Path, result: Dict,
                             raw_bytes: Optional[bytes] = None) -> None:
        if raw_bytes is None:
            raw_bytes = self._read_raw(filepath, result)
        if raw_bytes is None:
            return
        seen_codes: Set[str] = {f.get("code") for f in result["findings"] if f.get("code")}
        # Cheap presence check for major indicators when pikepdf can't open
        for marker, code, sev, cat, msg in [
            (b"/JavaScript", "PDF.ACTION_JAVASCRIPT", "HIGH",     "JavaScript Action",
             "JavaScript marker present (fallback byte scan)."),
            (b"/JS",         "PDF.ACTION_JAVASCRIPT", "HIGH",     "JavaScript Action",
             "JS marker present (fallback byte scan)."),
            (b"/Launch",     "PDF.ACTION_LAUNCH",     "CRITICAL", "Launch Action",
             "Launch action marker present (fallback byte scan)."),
            (b"/OpenAction", "PDF.OPENACTION",        "HIGH",     "OpenAction Trigger",
             "OpenAction marker present (fallback byte scan)."),
            (b"/EmbeddedFile","PDF.EMBEDDED_FILE",    "MEDIUM",   "Embedded File",
             "Embedded file marker present (fallback byte scan)."),
        ]:
            if marker in raw_bytes:
                self._add(result, seen_codes, {
                    "severity": sev,
                    "category": cat,
                    "message": msg,
                    "code": code,
                    "confidence": 0.4,  # lower no semantic walk
                })
        self._track_tool(result, "byte-scan-fallback", "success", type_="fallback")

    # ------------------------------------------------------------------
    # finalize: dedupe, score, summary
    # ------------------------------------------------------------------

    def _finalize(self, result: Dict) -> None:
        result["findings"] = self._dedupe(result["findings"])
        if not result["findings"]:
            result["findings"].append({
                "severity": "INFO",
                "category": "Clean",
                "message": "No suspicious elements detected.",
                "code": "PDF.CLEAN",
                "confidence": 0.8,
            })
        score, verdict, summary = self.scorer.score(result["findings"])
        result["score"] = score
        result["verdict"] = verdict
        result["summary"] = summary
        if verdict in ("malicious", "suspicious"):
            result["recommendations"] = [
                "MANUAL REVIEW REQUIRED" if verdict == "malicious"
                else "Manual review recommended",
                "Analyze in isolated environment",
                "Extract and review embedded JavaScript/files",
            ]

    @staticmethod
    def _dedupe(findings: List[Dict]) -> List[Dict]:
        """Group findings by (code, evidence-key) and merge.

        Identical-IOC findings collapse to one with the union of IOC sets."""
        bucketed: Dict[Tuple, Dict] = {}
        order: List[Tuple] = []
        for f in findings:
            ev = f.get("evidence") or {}
            key = (f.get("code"),
                   ev.get("object_id"),
                   ev.get("stream_path"),
                   ev.get("offset"))
            existing = bucketed.get(key)
            if existing is None:
                bucketed[key] = dict(f)
                order.append(key)
                continue
            # Merge IOCs
            existing_iocs = existing.get("iocs") or {}
            new_iocs = f.get("iocs") or {}
            existing["iocs"] = IOCExtractor.union(existing_iocs, new_iocs)
        return [bucketed[k] for k in order]

    @staticmethod
    def _add(result: Dict, seen_codes: Set[str], finding: Dict) -> None:
        """Append a finding, suppressing exact duplicate codes when no fresh evidence."""
        code = finding.get("code")
        if code and code in seen_codes and not finding.get("evidence"):
            return
        if code:
            seen_codes.add(code)
        result["findings"].append(finding)

    # ------------------------------------------------------------------
    # pikepdf accessor helpers (defensive never raise)
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_get(obj: Any, key: str) -> Any:
        try:
            v = obj.get(key)
            return v
        except Exception:
            return None

    @staticmethod
    def _safe_get_name(obj: Any, key: str) -> Optional[str]:
        try:
            v = obj.get(key)
            if v is None:
                return None
            return str(v)
        except Exception:
            return None

    @staticmethod
    def _safe_get_string(obj: Any, key: str) -> Optional[str]:
        try:
            v = obj.get(key)
            if v is None:
                return None
            if hasattr(v, "read_bytes"):
                return v.read_bytes().decode("utf-8", errors="ignore")
            return str(v)
        except Exception:
            return None

    @staticmethod
    def _is_stream(obj: Any) -> bool:
        return hasattr(obj, "read_bytes")

    @staticmethod
    def _is_dict_like(obj: Any) -> bool:
        return hasattr(obj, "get") and hasattr(obj, "keys")

    @staticmethod
    def _evidence_for(obj: Any) -> Dict[str, Any]:
        ev: Dict[str, Any] = {}
        try:
            objgen = getattr(obj, "objgen", None)
            if objgen is not None:
                ev["object_id"] = objgen[0]
        except Exception:
            pass
        try:
            ev["excerpt"] = repr(obj)[:200]
        except Exception:
            pass
        return ev
