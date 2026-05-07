"""PDFAnalyzer integration tests against test_pdfs/ fixtures.

These rely on pikepdf the conftest pdf_analyzer fixture skips the whole
file when pikepdf is not installed.
"""

from pathlib import Path

import pytest


def _codes(result):
    return {f.get("code") for f in result["findings"] if f.get("code")}


def test_clean_pdf_is_clean(pdf_analyzer, test_pdfs_dir):
    fixture = test_pdfs_dir / "test_clean.pdf"
    if not fixture.exists():
        pytest.skip(f"missing fixture: {fixture}")
    result = pdf_analyzer.analyze(fixture)
    assert result["verdict"] == "clean"
    assert "PDF.CLEAN" in _codes(result) or not any(
        c.startswith(("PDF.ACTION_", "PDF.JS_", "PDF.OPENACTION"))
        for c in _codes(result)
    )


def test_javascript_pdf_detects_js(pdf_analyzer, test_pdfs_dir):
    fixture = test_pdfs_dir / "test_javascript.pdf"
    if not fixture.exists():
        pytest.skip(f"missing fixture: {fixture}")
    result = pdf_analyzer.analyze(fixture)
    codes = _codes(result)
    assert "PDF.ACTION_JAVASCRIPT" in codes
    assert result["verdict"] in ("suspicious", "malicious")


def test_openaction_pdf_detects_trigger(pdf_analyzer, test_pdfs_dir):
    fixture = test_pdfs_dir / "test_openaction.pdf"
    if not fixture.exists():
        pytest.skip(f"missing fixture: {fixture}")
    result = pdf_analyzer.analyze(fixture)
    codes = _codes(result)
    # /OpenAction or /AA both trigger auto-execution on document open
    assert "PDF.OPENACTION" in codes or "PDF.AUTOACTION" in codes
    assert result["verdict"] in ("suspicious", "malicious")


def test_launch_pdf_is_malicious(pdf_analyzer, test_pdfs_dir):
    fixture = test_pdfs_dir / "test_launch.pdf"
    if not fixture.exists():
        pytest.skip(f"missing fixture: {fixture}")
    result = pdf_analyzer.analyze(fixture)
    codes = _codes(result)
    assert "PDF.ACTION_LAUNCH" in codes
    assert result["verdict"] == "malicious"


def test_embeddedfile_pdf_detects_embed(pdf_analyzer, test_pdfs_dir):
    fixture = test_pdfs_dir / "test_embeddedfile.pdf"
    if not fixture.exists():
        pytest.skip(f"missing fixture: {fixture}")
    result = pdf_analyzer.analyze(fixture)
    codes = _codes(result)
    assert any(c.startswith("PDF.EMBEDDED_FILE") for c in codes)


def test_acroform_pdf_detects_form(pdf_analyzer, test_pdfs_dir):
    fixture = test_pdfs_dir / "test_acroform.pdf"
    if not fixture.exists():
        pytest.skip(f"missing fixture: {fixture}")
    result = pdf_analyzer.analyze(fixture)
    codes = _codes(result)
    assert "PDF.ACROFORM" in codes


def test_richmedia_pdf_detects_action(pdf_analyzer, test_pdfs_dir):
    fixture = test_pdfs_dir / "test_richmedia.pdf"
    if not fixture.exists():
        pytest.skip(f"missing fixture: {fixture}")
    result = pdf_analyzer.analyze(fixture)
    codes = _codes(result)
    # /RichMedia annotation OR /RichMediaExecute action
    assert "PDF.RICHMEDIA" in codes or "PDF.ACTION_RICHMEDIAEXECUTE" in codes


def test_gotor_gotoe_pdf_detects_remote(pdf_analyzer, test_pdfs_dir):
    fixture = test_pdfs_dir / "test_gotor_gotoe.pdf"
    if not fixture.exists():
        pytest.skip(f"missing fixture: {fixture}")
    result = pdf_analyzer.analyze(fixture)
    codes = _codes(result)
    assert "PDF.ACTION_GOTOR" in codes or "PDF.ACTION_GOTOE" in codes


def test_objstm_pdf_detects_or_inspects(pdf_analyzer, test_pdfs_dir):
    fixture = test_pdfs_dir / "test_objstm.pdf"
    if not fixture.exists():
        pytest.skip(f"missing fixture: {fixture}")
    result = pdf_analyzer.analyze(fixture)
    # Either we found the JS hidden in an ObjStm, or the action surfaced
    codes = _codes(result)
    assert (
        "PDF.OBJSTM_HIDES_JS" in codes
        or "PDF.ACTION_JAVASCRIPT" in codes
        or result["verdict"] != "clean"
    )


def test_result_shape_has_required_keys(pdf_analyzer, test_pdfs_dir):
    fixture = test_pdfs_dir / "test_clean.pdf"
    if not fixture.exists():
        pytest.skip(f"missing fixture: {fixture}")
    result = pdf_analyzer.analyze(fixture)
    # Backward-compatible keys
    for k in ("file", "type", "timestamp", "findings", "tools_used"):
        assert k in result, f"missing key: {k}"
    # New keys
    for k in ("verdict", "score", "summary", "iocs", "statistics"):
        assert k in result, f"missing key: {k}"
    assert result["verdict"] in ("clean", "suspicious", "malicious")
    assert 0 <= result["score"] <= 100


def test_password_candidate_extraction():
    """Password-hint regex on email body does not need pikepdf."""
    from tools.custom.pdf_analyzer import PDFAnalyzer
    body = "Hello, the password is hunter2 please open the attached PDF."
    candidates = PDFAnalyzer._password_candidates_from_body(body)
    assert "hunter2" in candidates


def test_polyglot_detection_byte_level(tmp_path: Path):
    """Trailing PE after %%EOF should fire PDF.POLYGLOT pure-byte path."""
    from tools.custom.pdf_analyzer import PDFAnalyzer
    fake = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog >> endobj\n"
        b"trailer << /Root 1 0 R >>\n"
        b"%%EOF\n"
        + b"MZ" + b"\x90" * 64  # PE-ish trailing bytes
    )
    p = tmp_path / "polyglot.pdf"
    p.write_bytes(fake)
    analyzer = PDFAnalyzer()
    result = {"findings": [], "tools_used": [], "iocs": {}, "statistics": {}}
    analyzer._check_polyglot(fake, result)
    codes = {f.get("code") for f in result["findings"]}
    assert "PDF.POLYGLOT" in codes
