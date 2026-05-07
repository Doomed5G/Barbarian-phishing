#!/usr/bin/env python3
"""
Office analyzer replaces the oledump.py / oleid.py / olevba.py subprocess
pipeline with an in-process implementation built on `oletools` (used as a
library, not via subprocess), plus zip + defusedxml for OOXML structural
checks and msoffcrypto-tool for encrypted-document detection.

Substrates handled:
    * OLE2 (.doc / .xls / .ppt / .msg)         -> _analyze_ole2 + _analyze_vba
    * OOXML (.docx / .xlsx / .pptx + .docm/.xlsm/.pptm) -> _analyze_ooxml + _analyze_vba
    * RTF (.rtf)                               -> _analyze_rtf
    * Encrypted (any of the above)             -> _analyze_encrypted

Every code path emits structured findings whose `code` is a stable ID
consumed by tools.custom.scoring.ScoreEngine.
"""

import hashlib
import io
import re
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Optional third-party imports -- degrade gracefully when missing
# ---------------------------------------------------------------------------
try:
    from oletools.olevba import (
        VBA_Parser,
        detect_autoexec,
        detect_suspicious,
        detect_patterns,
    )
    from oletools.oleid import OleID
    from oletools.rtfobj import RtfObjParser
    HAS_OLETOOLS = True
except ImportError:
    HAS_OLETOOLS = False

try:
    import olefile
    HAS_OLEFILE = True
except ImportError:
    HAS_OLEFILE = False

try:
    import msoffcrypto
    HAS_MSOFFCRYPTO = True
except ImportError:
    HAS_MSOFFCRYPTO = False

try:
    from defusedxml import ElementTree as DefusedET
    HAS_DEFUSEDXML = True
except ImportError:
    HAS_DEFUSEDXML = False

from .iocs import IOCExtractor
from .scoring import ScoreEngine


# ---------------------------------------------------------------------------
# Magic bytes
# ---------------------------------------------------------------------------
_MAGIC_OLE2 = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_MAGIC_ZIP = b"PK\x03\x04"
_MAGIC_PE = b"MZ"
_RTF_PREFIXES = (b"{\\rtf", b"{\\\rtf", b"{ \\rtf")  # tolerate whitespace

# OOXML relationship types we treat as "external" attack vectors
_REL_TYPE_TEMPLATE = "attachedTemplate"
_REL_TYPE_OLEOBJECT = "oleObject"
_REL_TYPE_FRAME = "frame"
_REL_TYPE_HYPERLINK = "hyperlink"
_REL_TYPE_IMAGE = "image"

# Common Office passwords to try for encrypted docs
_OFFICE_PASSWORD_GUESSES = ["", "1234", "12345", "123456", "password",
                            "VelvetSweatshop"]  # Excel default

# RTF object class names with known exploit value
_RTF_DANGEROUS_CLASSES = {
    "Equation.3":       ("OFFICE.RTF_OLE_EQUATION", "CRITICAL",
                         "RTF embeds Equation.3 OLE object (CVE-2017-11882 / CVE-2018-0802)"),
    "Equation.2":       ("OFFICE.RTF_OLE_EQUATION", "CRITICAL",
                         "RTF embeds Equation.2 OLE object (CVE-2017-11882)"),
    "OLE2Link":         ("OFFICE.RTF_OLE_LINK", "HIGH",
                         "RTF embeds OLE2Link object (CVE-2017-0199 family)"),
    "Package":          ("OFFICE.RTF_OLE_PACKAGE", "HIGH",
                         "RTF embeds OLE Package object (file-drop vector)"),
    "Packager Shell Object": ("OFFICE.RTF_OLE_PACKAGE", "HIGH",
                         "RTF embeds Packager Shell Object"),
}


class OfficeAnalyzer:
    """Replaces analyze_ole + enhance_office in barbarian-phishing.py."""

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
        filepath = Path(filepath)
        result = self._base_result(filepath)

        if not HAS_OLETOOLS:
            result["findings"].append({
                "severity": "WARNING",
                "category": "Setup",
                "message": "oletools not installed install with `pip install oletools`",
                "code": "SETUP.OLETOOLS_MISSING",
            })
            self._track_tool(result, "oletools", "unavailable")
            return self._finalize(result)

        head = self._read_head(filepath, 16)
        if head is None:
            return self._finalize(result)

        # ---- Encryption check first ---------------------------------------
        decrypted_buf = self._handle_encryption(filepath, email_body, result)
        if decrypted_buf is not None:
            # Re-dispatch on the decrypted bytes
            self._dispatch_buffer(decrypted_buf, result, source="decrypted")
            return self._finalize(result)

        if any(f.get("code") == "OFFICE.ENCRYPTED" for f in result["findings"]):
            # Encrypted, no successful decrypt stop; further parsing useless
            return self._finalize(result)

        # ---- Dispatch by magic --------------------------------------------
        self._dispatch_path(filepath, head, result)

        return self._finalize(result)

    # ------------------------------------------------------------------
    # Skeleton helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _base_result(filepath: Path) -> Dict[str, Any]:
        return {
            "file": str(filepath),
            "type": "Office Document",
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "tools_used": [],
            "iocs": {},
            "statistics": {},
        }

    @staticmethod
    def _track_tool(result: Dict, name: str, status: str,
                    type_: str = "primary", error: str = "",
                    note: str = "") -> None:
        entry = {
            "name": name,
            "status": status,
            "type": type_,
            "timestamp": datetime.now().isoformat(),
        }
        if error:
            entry["error"] = error
        if note:
            entry["note"] = note
        result["tools_used"].append(entry)

    @staticmethod
    def _read_head(filepath: Path, n: int) -> Optional[bytes]:
        try:
            with open(filepath, "rb") as fp:
                return fp.read(n)
        except OSError:
            return None

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def _dispatch_path(self, filepath: Path, head: bytes, result: Dict) -> None:
        if head.startswith(_RTF_PREFIXES) or head.lstrip().startswith(b"{\\rtf"):
            self._analyze_rtf(filepath, result)
            return
        if head.startswith(_MAGIC_OLE2):
            self._analyze_ole2(filepath, result)
            self._analyze_vba(filepath, result)
            return
        if head.startswith(_MAGIC_ZIP):
            self._analyze_ooxml(filepath, result)
            self._analyze_vba(filepath, result)
            return
        # Unknown: try VBA_Parser anyway covers MHT, Word2003-XML,
        # PowerPoint legacy, and anything else oletools auto-detects.
        self._analyze_vba(filepath, result)

    def _dispatch_buffer(self, buf: bytes, result: Dict, source: str) -> None:
        head = buf[:16]
        if head.startswith(_RTF_PREFIXES) or head.lstrip().startswith(b"{\\rtf"):
            self._analyze_rtf_data(buf, result, source=source)
            return
        if head.startswith(_MAGIC_OLE2):
            self._analyze_ole2_data(buf, result, source=source)
            self._analyze_vba_data(buf, result, source=source)
            return
        if head.startswith(_MAGIC_ZIP):
            self._analyze_ooxml_data(buf, result, source=source)
            self._analyze_vba_data(buf, result, source=source)
            return
        self._analyze_vba_data(buf, result, source=source)

    # ------------------------------------------------------------------
    # Encryption
    # ------------------------------------------------------------------

    def _handle_encryption(
        self,
        filepath: Path,
        email_body: str,
        result: Dict,
    ) -> Optional[bytes]:
        """Detect encrypted Office; on weak/empty password, return decrypted bytes."""
        if not HAS_MSOFFCRYPTO:
            return None
        try:
            with open(filepath, "rb") as fp:
                of = msoffcrypto.OfficeFile(fp)
                try:
                    encrypted = of.is_encrypted()
                except Exception:
                    encrypted = False
                if not encrypted:
                    return None

                # Encrypted try guesses
                guesses = list(_OFFICE_PASSWORD_GUESSES)
                guesses.extend(self._password_candidates_from_body(email_body))
                for pwd in guesses:
                    try:
                        of.load_key(password=pwd)
                    except Exception:
                        continue
                    out = io.BytesIO()
                    try:
                        of.decrypt(out)
                    except Exception:
                        continue
                    self._add(result, set(), {
                        "severity": "HIGH",
                        "category": "Encrypted Office Document",
                        "message": (
                            f"Office document is password-protected and unlocks "
                            f"with the trivial password '{pwd}' recursing on decrypted bytes."
                            if pwd else
                            "Office document encrypted with empty password "
                            "recursing on decrypted bytes."
                        ),
                        "code": "OFFICE.ENCRYPTED_WEAK_PASS",
                        "evidence": {"excerpt": f"password={pwd!r}"},
                        "confidence": 0.95,
                    })
                    self._track_tool(result, "msoffcrypto", "success")
                    return out.getvalue()

                # Couldn't unlock
                self._add(result, set(), {
                    "severity": "MEDIUM",
                    "category": "Encrypted Office Document",
                    "message": "Office document is password-protected content not analyzable.",
                    "code": "OFFICE.ENCRYPTED",
                    "confidence": 0.9,
                })
                self._track_tool(result, "msoffcrypto", "success",
                                 note="encrypted, password not guessed")
                return None
        except Exception as e:
            self._track_tool(result, "msoffcrypto", "error", error=str(e)[:200])
            return None

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
    # OLE2 (.doc / .xls / .ppt / .msg)
    # ------------------------------------------------------------------

    def _analyze_ole2(self, filepath: Path, result: Dict) -> None:
        seen_codes = self._existing_codes(result)
        if HAS_OLEFILE:
            try:
                ole = olefile.OleFileIO(str(filepath))
            except Exception as e:
                self._add(result, seen_codes, {
                    "severity": "WARNING",
                    "category": "OLE2 Parse Error",
                    "message": f"olefile could not open OLE2 container: {e}",
                    "code": "OFFICE.MALFORMED",
                    "confidence": 0.8,
                })
                self._track_tool(result, "olefile", "error", error=str(e)[:200])
                return
            try:
                streams = ole.listdir(streams=True, storages=False)
                result["statistics"]["ole_streams"] = len(streams)
                self._track_tool(result, "olefile", "success")
            finally:
                try:
                    ole.close()
                except Exception:
                    pass

        # OleID indicators
        try:
            oleid = OleID(str(filepath))
            indicators = oleid.check()
            self._fold_oleid_indicators(indicators, result, seen_codes)
            self._track_tool(result, "OleID", "success")
        except Exception as e:
            self._track_tool(result, "OleID", "error", error=str(e)[:200])

    def _analyze_ole2_data(self, buf: bytes, result: Dict, source: str) -> None:
        seen_codes = self._existing_codes(result)
        try:
            ole = olefile.OleFileIO(io.BytesIO(buf)) if HAS_OLEFILE else None
            if ole is not None:
                try:
                    streams = ole.listdir(streams=True, storages=False)
                    result["statistics"][f"ole_streams_{source}"] = len(streams)
                finally:
                    try:
                        ole.close()
                    except Exception:
                        pass
        except Exception as e:
            self._add(result, seen_codes, {
                "severity": "WARNING",
                "category": "OLE2 Parse Error",
                "message": f"olefile could not open decrypted OLE2: {e}",
                "code": "OFFICE.MALFORMED",
                "confidence": 0.7,
            })

    def _fold_oleid_indicators(
        self,
        indicators: Iterable,
        result: Dict,
        seen_codes: Set[str],
    ) -> None:
        for ind in indicators:
            try:
                name = getattr(ind, "name", "") or ""
                value = getattr(ind, "value", None)
                if not name or value is None:
                    continue
                # Only emit "true" indicators or risky ones
                # OleID returns mostly bool/str; skip when value is the default
                if name.lower() in ("flash", "vba_macros", "xlm_macros",
                                    "external_relationships"):
                    if value:
                        result["statistics"][f"oleid_{name.lower()}"] = str(value)
            except Exception:
                continue

    # ------------------------------------------------------------------
    # OOXML
    # ------------------------------------------------------------------

    def _analyze_ooxml(self, filepath: Path, result: Dict) -> None:
        try:
            with open(filepath, "rb") as fp:
                self._analyze_ooxml_data(fp.read(), result, source="primary")
        except OSError as e:
            self._track_tool(result, "ooxml-zip", "error", error=str(e)[:200])

    def _analyze_ooxml_data(self, buf: bytes, result: Dict, source: str) -> None:
        seen_codes = self._existing_codes(result)
        ioc_buckets: List[Dict[str, List[str]]] = []
        try:
            zf = zipfile.ZipFile(io.BytesIO(buf))
        except zipfile.BadZipFile:
            self._add(result, seen_codes, {
                "severity": "MEDIUM",
                "category": "Invalid OOXML",
                "message": "OOXML container is not a valid zip.",
                "code": "OFFICE.MALFORMED",
                "confidence": 0.85,
            })
            self._track_tool(result, "ooxml-zip", "error", error="BadZipFile")
            return

        try:
            namelist = zf.namelist()
            result["statistics"]["ooxml_parts"] = len(namelist)

            # 1) DDE field codes
            self._inspect_ooxml_dde(zf, namelist, result, seen_codes)

            # 2) External relationships
            self._inspect_ooxml_rels(zf, namelist, result, seen_codes, ioc_buckets)

            # 3) Embedded OLE objects
            self._inspect_ooxml_embedded(zf, namelist, result, seen_codes)

            # 4) Remote images (NTLM-leak / tracking pixels) covered by rels

            self._track_tool(result, "ooxml-zip", "success")
        finally:
            try:
                zf.close()
            except Exception:
                pass

        # Fold IOCs
        if ioc_buckets:
            existing = result.get("iocs") or {}
            result["iocs"] = IOCExtractor.union(existing, *ioc_buckets)

    def _inspect_ooxml_dde(
        self,
        zf: zipfile.ZipFile,
        namelist: List[str],
        result: Dict,
        seen_codes: Set[str],
    ) -> None:
        # DDE field codes are always inside word/document.xml-style XML parts.
        # The legitimate way to spot them is to find <w:fldChar/> + DDEAUTO/DDE
        # inside the same field structure. Cheap heuristic: look for the
        # field-code text "DDEAUTO" or "DDE " preceded by `<w:instrText`,
        # to avoid false positives where the literal word appears as content.
        for name in namelist:
            if not (name.endswith(".xml")):
                continue
            try:
                blob = zf.read(name).decode("utf-8", errors="ignore")
            except Exception:
                continue

            # Field-code structure indicator
            has_fld = ("<w:fldChar" in blob or
                       "<w:instrText" in blob or
                       "instrText" in blob)
            if re.search(r"(?i)\bDDEAUTO\b", blob) and has_fld:
                self._add(result, seen_codes, {
                    "severity": "CRITICAL",
                    "category": "DDE Auto-Execute",
                    "message": f"DDEAUTO field code in {name}",
                    "code": "OFFICE.DDEAUTO",
                    "evidence": {"stream_path": name,
                                 "excerpt": self._snip(blob, "DDEAUTO")},
                    "confidence": 0.9,
                    "mitre_attack": ["T1559.002"],
                })
                # AUTOEXEC marker for correlation
                self._add(result, seen_codes, {
                    "severity": "HIGH",
                    "category": "Auto-Execute",
                    "message": "Document auto-executes via DDEAUTO.",
                    "code": "OFFICE.AUTOEXEC",
                    "confidence": 0.9,
                })
            elif re.search(r"(?i)\bDDE\b", blob) and has_fld:
                self._add(result, seen_codes, {
                    "severity": "HIGH",
                    "category": "DDE Field Code",
                    "message": f"DDE field code in {name}",
                    "code": "OFFICE.DDE",
                    "evidence": {"stream_path": name,
                                 "excerpt": self._snip(blob, "DDE")},
                    "confidence": 0.7,
                    "mitre_attack": ["T1559.002"],
                })

    def _inspect_ooxml_rels(
        self,
        zf: zipfile.ZipFile,
        namelist: List[str],
        result: Dict,
        seen_codes: Set[str],
        ioc_buckets: List[Dict[str, List[str]]],
    ) -> None:
        rels = [n for n in namelist if n.endswith(".rels")]
        for name in rels:
            try:
                blob = zf.read(name).decode("utf-8", errors="ignore")
            except Exception:
                continue

            relations = self._parse_rels(blob)
            for rel in relations:
                target = rel.get("Target", "")
                target_mode = rel.get("TargetMode", "")
                rel_type = rel.get("Type", "").rsplit("/", 1)[-1]

                is_external = (target_mode == "External" or
                               target.lower().startswith(("http://", "https://")))
                if not is_external:
                    continue

                # Template injection (CVE-2017-0199 family)
                if rel_type == _REL_TYPE_TEMPLATE or rel_type == _REL_TYPE_OLEOBJECT:
                    self._add(result, seen_codes, {
                        "severity": "CRITICAL",
                        "category": "External Template / OLE",
                        "message": (
                            f"Document loads remote {rel_type} from {target} "
                            f"(CVE-2017-0199 family)."
                        ),
                        "code": "OFFICE.EXTERNAL_TEMPLATE",
                        "evidence": {"stream_path": name, "excerpt": target},
                        "confidence": 0.95,
                        "mitre_attack": ["T1221"],
                    })
                    # Also fire EXTERNAL_HTTP so the correlation rule
                    # (TEMPLATE + EXTERNAL_HTTP) lights up.
                    self._add(result, seen_codes, {
                        "severity": "MEDIUM",
                        "category": "External Resource",
                        "message": f"External HTTP target: {target}",
                        "code": "OFFICE.EXTERNAL_HTTP",
                        "evidence": {"stream_path": name, "excerpt": target},
                        "confidence": 0.95,
                    })
                    ioc_buckets.append({"urls": [target]})
                    continue

                if rel_type == _REL_TYPE_IMAGE:
                    self._add(result, seen_codes, {
                        "severity": "MEDIUM",
                        "category": "Remote Image",
                        "message": (
                            f"Document loads remote image {target} "
                            "(possible NTLM-leak / tracking pixel)."
                        ),
                        "code": "OFFICE.EXTERNAL_REMOTE_IMG",
                        "evidence": {"stream_path": name, "excerpt": target},
                        "confidence": 0.85,
                    })
                    ioc_buckets.append({"urls": [target]})
                    continue

                # Generic external resource
                self._add(result, seen_codes, {
                    "severity": "MEDIUM",
                    "category": "External Resource",
                    "message": f"External target ({rel_type}) {target} in {name}",
                    "code": "OFFICE.EXTERNAL_HTTP",
                    "evidence": {"stream_path": name, "excerpt": target},
                    "confidence": 0.75,
                })
                ioc_buckets.append({"urls": [target]})

    @staticmethod
    def _parse_rels(xml_text: str) -> List[Dict[str, str]]:
        """Return a list of dicts of relationship attribute maps."""
        relations: List[Dict[str, str]] = []
        if HAS_DEFUSEDXML:
            try:
                root = DefusedET.fromstring(xml_text)
                for el in root.iter():
                    if el.tag.lower().endswith("relationship"):
                        relations.append(dict(el.attrib))
                return relations
            except Exception:
                pass
        # Regex fallback
        for m in re.finditer(
            r'<Relationship\b([^/>]*)/?>', xml_text, re.IGNORECASE,
        ):
            attrs = dict(re.findall(r'([A-Za-z][\w:]*)\s*=\s*"([^"]*)"', m.group(1)))
            relations.append(attrs)
        return relations

    def _inspect_ooxml_embedded(
        self,
        zf: zipfile.ZipFile,
        namelist: List[str],
        result: Dict,
        seen_codes: Set[str],
    ) -> None:
        emb_paths = [
            n for n in namelist
            if "/embeddings/" in n and n.endswith(".bin")
        ]
        for name in emb_paths:
            try:
                data = zf.read(name)
            except Exception:
                continue
            sha256 = hashlib.sha256(data).hexdigest() if data else None
            head = data[:8]

            if data.startswith(_MAGIC_PE) or _MAGIC_PE in data[:512]:
                self._add(result, seen_codes, {
                    "severity": "CRITICAL",
                    "category": "Embedded PE Executable",
                    "message": f"Embedded OLE object {name} contains PE executable bytes.",
                    "code": "OFFICE.EMBEDDED_OLE_PE",
                    "evidence": {"stream_path": name},
                    "iocs": {"hashes_sha256": [sha256] if sha256 else []},
                    "confidence": 0.95,
                    "mitre_attack": ["T1027.009", "T1204.002"],
                })
                continue

            self._add(result, seen_codes, {
                "severity": "MEDIUM",
                "category": "Embedded OLE Object",
                "message": f"Document embeds OLE object {name} ({len(data)} bytes).",
                "code": "OFFICE.EMBEDDED_OLE",
                "evidence": {"stream_path": name},
                "iocs": {"hashes_sha256": [sha256] if sha256 else []},
                "confidence": 0.85,
            })

            # Recurse: if the embedded blob is itself an OLE2 with VBA,
            # let VBA_Parser pick it up directly from bytes.
            if data.startswith(_MAGIC_OLE2):
                self._analyze_vba_data(data, result, source=name)

    # ------------------------------------------------------------------
    # RTF
    # ------------------------------------------------------------------

    def _analyze_rtf(self, filepath: Path, result: Dict) -> None:
        try:
            data = filepath.read_bytes()
        except OSError as e:
            self._track_tool(result, "rtfobj", "error", error=str(e)[:200])
            return
        self._analyze_rtf_data(data, result, source="primary")

    def _analyze_rtf_data(self, data: bytes, result: Dict, source: str) -> None:
        seen_codes = self._existing_codes(result)
        result["type"] = "RTF"
        try:
            parser = RtfObjParser(data)
            parser.parse()
        except Exception as e:
            self._add(result, seen_codes, {
                "severity": "WARNING",
                "category": "RTF Parse Error",
                "message": f"rtfobj could not parse RTF: {e}",
                "code": "OFFICE.MALFORMED",
                "confidence": 0.7,
            })
            self._track_tool(result, "rtfobj", "error", error=str(e)[:200])
            return

        objects = list(getattr(parser, "objects", []))
        result["statistics"]["rtf_objects"] = len(objects)

        for rtf_obj in objects:
            self._inspect_rtf_object(rtf_obj, result, seen_codes)

        self._track_tool(result, "rtfobj", "success")

    def _inspect_rtf_object(
        self,
        rtf_obj: Any,
        result: Dict,
        seen_codes: Set[str],
    ) -> None:
        is_ole = bool(getattr(rtf_obj, "is_ole", False))
        class_name = (getattr(rtf_obj, "class_name", b"") or b"")
        if isinstance(class_name, bytes):
            class_name = class_name.decode("utf-8", errors="ignore")

        if not is_ole:
            return

        mapping = _RTF_DANGEROUS_CLASSES.get(class_name)
        if mapping is not None:
            code, sev, msg = mapping
            self._add(result, seen_codes, {
                "severity": sev,
                "category": "RTF Embedded OLE",
                "message": msg,
                "code": code,
                "evidence": {"excerpt": class_name},
                "confidence": 0.95,
                "mitre_attack": ["T1203", "T1204.002"],
            })

        # Package payload check for PE inside
        if class_name in ("Package", "Packager Shell Object"):
            payload = getattr(rtf_obj, "olepkgdata", None) or \
                      getattr(rtf_obj, "oledata", None) or b""
            if isinstance(payload, str):
                payload = payload.encode("latin-1", errors="ignore")
            if payload and (payload.startswith(_MAGIC_PE) or
                            _MAGIC_PE in payload[:1024]):
                sha256 = hashlib.sha256(payload).hexdigest()
                self._add(result, seen_codes, {
                    "severity": "CRITICAL",
                    "category": "RTF Package PE Drop",
                    "message": "RTF Package object contains PE executable bytes.",
                    "code": "OFFICE.RTF_OLE_PACKAGE_PE",
                    "iocs": {"hashes_sha256": [sha256]},
                    "confidence": 0.95,
                    "mitre_attack": ["T1027.009", "T1204.002"],
                })

    # ------------------------------------------------------------------
    # VBA pipeline (OLE2 + OOXML alike)
    # ------------------------------------------------------------------

    def _analyze_vba(self, filepath: Path, result: Dict) -> None:
        try:
            vba = VBA_Parser(str(filepath))
        except Exception as e:
            self._track_tool(result, "VBA_Parser", "error", error=str(e)[:200])
            return
        try:
            self._run_vba_pipeline(vba, result, source="primary")
        finally:
            try:
                vba.close()
            except Exception:
                pass

    def _analyze_vba_data(self, data: bytes, result: Dict, source: str) -> None:
        try:
            vba = VBA_Parser(filename=source, data=data)
        except Exception as e:
            self._track_tool(result, "VBA_Parser", "error",
                             error=f"{source}: {e}"[:200])
            return
        try:
            self._run_vba_pipeline(vba, result, source=source)
        finally:
            try:
                vba.close()
            except Exception:
                pass

    def _run_vba_pipeline(
        self,
        vba: "VBA_Parser",
        result: Dict,
        source: str,
    ) -> None:
        seen_codes = self._existing_codes(result)
        ioc_buckets: List[Dict[str, List[str]]] = []

        # Macros?
        try:
            has_vba = vba.detect_vba_macros()
        except Exception:
            has_vba = False
        try:
            has_xlm = vba.detect_xlm_macros() if hasattr(vba, "detect_xlm_macros") else False
        except Exception:
            has_xlm = False

        if has_xlm:
            self._add(result, seen_codes, {
                "severity": "HIGH",
                "category": "Excel 4.0 Macros",
                "message": "Document contains Excel 4.0 (XLM) macros.",
                "code": "OFFICE.XLM_MACROS",
                "confidence": 0.95,
                "mitre_attack": ["T1059"],
            })

        if not has_vba:
            self._track_tool(result, "VBA_Parser", "success",
                             note=f"no VBA macros ({source})")
            self._merge_iocs(result, ioc_buckets)
            return

        self._add(result, seen_codes, {
            "severity": "HIGH",
            "category": "VBA Macros",
            "message": "Document contains VBA macros.",
            "code": "OFFICE.VBA_PRESENT",
            "confidence": 1.0,
            "mitre_attack": ["T1059.005"],
        })

        # Iterate ALL macros (this fixes the historical "break after first
        # suspicious keyword" bug collect every hit).
        modules = 0
        try:
            macros = list(vba.extract_all_macros())
        except Exception as e:
            self._track_tool(result, "VBA_Parser", "error",
                             error=f"extract_all_macros: {e}"[:200])
            return

        for filename, stream_path, vba_filename, vba_code in macros:
            modules += 1
            if not vba_code:
                continue
            try:
                vba_text = (vba_code if isinstance(vba_code, str)
                            else vba_code.decode("utf-8", errors="ignore"))
            except Exception:
                vba_text = str(vba_code)

            self._inspect_vba_module(
                vba_text, stream_path, vba_filename, result, seen_codes, ioc_buckets,
            )

        result["statistics"]["vba_modules"] = modules
        self._track_tool(result, "VBA_Parser", "success",
                         note=f"{modules} macro module(s) ({source})")
        self._merge_iocs(result, ioc_buckets)

    def _inspect_vba_module(
        self,
        vba_text: str,
        stream_path: str,
        vba_filename: str,
        result: Dict,
        seen_codes: Set[str],
        ioc_buckets: List[Dict[str, List[str]]],
    ) -> None:
        deobf = self.iocs.deobfuscate_string(vba_text)

        # Auto-exec keywords (catches AutoOpen, Document_Open, Workbook_Open,
        # Auto_Close, Document_Close, Workbook_Activate, etc.)
        try:
            autoexec = detect_autoexec(deobf)
        except Exception:
            autoexec = []
        for keyword, description in autoexec:
            self._add(result, seen_codes, {
                "severity": "CRITICAL",
                "category": "Auto-Execute Macro",
                "message": f'VBA auto-execute: {keyword} {description}',
                "code": "OFFICE.VBA_AUTOEXEC",
                "evidence": {"stream_path": stream_path or vba_filename,
                             "excerpt": keyword},
                "confidence": 0.95,
                "mitre_attack": ["T1204.002", "T1059.005"],
            })

        # Suspicious keywords (catches Shell, CreateObject, WScript, PowerShell,
        # URLDownloadToFile, etc.)
        try:
            suspicious = detect_suspicious(deobf)
        except Exception:
            suspicious = []
        for keyword, description in suspicious:
            kw_lower = keyword.lower()
            # Sub-classify a couple of high-impact keywords for correlation
            if any(s in kw_lower for s in ("shell", "wscript", "createobject")):
                code = "OFFICE.VBA_SHELL"
                sev = "CRITICAL"
            elif any(s in kw_lower for s in ("download", "urlmon", "winhttp",
                                              "xmlhttp", "msxml2")):
                code = "OFFICE.VBA_DOWNLOAD"
                sev = "CRITICAL"
            else:
                code = "OFFICE.VBA_SUSPICIOUS"
                sev = "HIGH"
            self._add(result, seen_codes, {
                "severity": sev,
                "category": "Suspicious VBA Code",
                "message": f"VBA uses {keyword} {description}",
                "code": code,
                "evidence": {"stream_path": stream_path or vba_filename,
                             "excerpt": keyword},
                "confidence": 0.9,
                "mitre_attack": ["T1059.005"],
            })

        # IOC patterns (URLs, IPs, exec names, hex, base64)
        try:
            patterns = detect_patterns(deobf)
        except Exception:
            patterns = []
        bucket: Dict[str, List[str]] = {}
        for pattern_type, value in patterns:
            pt = (pattern_type or "").lower()
            if "url" in pt:
                bucket.setdefault("urls", []).append(value)
            elif "ip" in pt:
                bucket.setdefault("ips", []).append(value)
            elif "executable" in pt:
                bucket.setdefault("paths", []).append(value)
        if bucket:
            ioc_buckets.append(bucket)

        # Run our own extractor too (catches things olevba's regex misses)
        ioc_buckets.append(self.iocs.extract(deobf))

        # Surface URL/IP IOCs as their own findings (so scoring can fire)
        merged = IOCExtractor.union(*ioc_buckets) if ioc_buckets else {}
        if merged.get("urls"):
            self._add(result, seen_codes, {
                "severity": "HIGH",
                "category": "VBA URL IOC",
                "message": f"VBA macro references URL(s): "
                           f"{', '.join(merged['urls'][:3])}"
                           + (" …" if len(merged["urls"]) > 3 else ""),
                "code": "OFFICE.VBA_IOC_URL",
                "evidence": {"stream_path": stream_path or vba_filename},
                "iocs": {"urls": list(merged["urls"])},
                "confidence": 0.85,
            })
        if merged.get("ips"):
            self._add(result, seen_codes, {
                "severity": "HIGH",
                "category": "VBA IP IOC",
                "message": f"VBA macro references IP(s): {', '.join(merged['ips'][:3])}",
                "code": "OFFICE.VBA_IOC_IP",
                "evidence": {"stream_path": stream_path or vba_filename},
                "iocs": {"ips": list(merged["ips"])},
                "confidence": 0.85,
            })

        # Heavy obfuscation heuristic: a long-ish source with many Chr/concat
        # tokens is suspicious in itself.
        chr_count = len(re.findall(r"(?i)\bChrW?\(", vba_text))
        concat_count = len(re.findall(r'"\s*[&+]\s*"', vba_text))
        if chr_count >= 8 or concat_count >= 12:
            self._add(result, seen_codes, {
                "severity": "MEDIUM",
                "category": "Obfuscated VBA",
                "message": (
                    f"VBA module shows obfuscation markers "
                    f"(Chr() x{chr_count}, concat x{concat_count})."
                ),
                "code": "OFFICE.VBA_OBFUSCATED",
                "evidence": {"stream_path": stream_path or vba_filename},
                "confidence": 0.75,
            })

    # ------------------------------------------------------------------
    # Finalize
    # ------------------------------------------------------------------

    def _finalize(self, result: Dict) -> Dict[str, Any]:
        result["findings"] = self._dedupe(result["findings"])
        if not result["findings"]:
            result["findings"].append({
                "severity": "INFO",
                "category": "Clean",
                "message": "No suspicious elements detected.",
                "code": "OFFICE.CLEAN",
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
                "Do not enable macros",
                "Analyze in isolated environment",
                "Extract and review macro code",
            ]
        return result

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _existing_codes(result: Dict) -> Set[str]:
        return {f.get("code") for f in result["findings"] if f.get("code")}

    @staticmethod
    def _add(result: Dict, seen_codes: Set[str], finding: Dict) -> None:
        code = finding.get("code")
        # For codes that should fire only once per analysis without fresh
        # evidence, suppress duplicates.
        if code and code in seen_codes and not finding.get("evidence"):
            return
        if code:
            seen_codes.add(code)
        result["findings"].append(finding)

    @staticmethod
    def _dedupe(findings: List[Dict]) -> List[Dict]:
        bucketed: Dict[Tuple, Dict] = {}
        order: List[Tuple] = []
        for f in findings:
            ev = f.get("evidence") or {}
            key = (
                f.get("code"),
                ev.get("stream_path"),
                ev.get("excerpt"),
            )
            existing = bucketed.get(key)
            if existing is None:
                bucketed[key] = dict(f)
                order.append(key)
                continue
            existing_iocs = existing.get("iocs") or {}
            new_iocs = f.get("iocs") or {}
            existing["iocs"] = IOCExtractor.union(existing_iocs, new_iocs)
        return [bucketed[k] for k in order]

    @staticmethod
    def _merge_iocs(result: Dict, buckets: List[Dict[str, List[str]]]) -> None:
        if not buckets:
            return
        existing = result.get("iocs") or {}
        result["iocs"] = IOCExtractor.union(existing, *buckets)

    @staticmethod
    def _snip(text: str, needle: str, span: int = 60) -> str:
        i = text.lower().find(needle.lower())
        if i < 0:
            return text[:200]
        return text[max(0, i - span): i + len(needle) + span][:200]
