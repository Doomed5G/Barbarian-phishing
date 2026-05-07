"""End-to-end test for EML mode.

Builds a synthetic .eml in a tmp dir with a real malicious PDF attachment
(reuses the existing test_pdfs/test_javascript.pdf fixture), then runs the
EML parser to confirm:
    * .eml is parsed
    * attachments land in <email_folder>/attached_files/<original-name>
    * URLs from the HTML body are written to <email_folder>/link.txt
    * a downstream PDF analysis on the extracted attachment fires the right
      codes
"""

from email.message import EmailMessage
from pathlib import Path
import importlib.util
import sys

import pytest


# --- import the AttachmentAnalyzer class out of the hyphenated main script ----
@pytest.fixture(scope="session")
def AttachmentAnalyzer():
    root = Path(__file__).resolve().parent.parent
    main = root / "barbarian-phishing.py"
    spec = importlib.util.spec_from_file_location("barbarian_phishing", main)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(root))
    try:
        spec.loader.exec_module(mod)
    finally:
        if str(root) in sys.path:
            sys.path.remove(str(root))
    return mod.AttachmentAnalyzer


def _build_eml(out: Path, pdf_bytes: bytes) -> None:
    msg = EmailMessage()
    msg["From"] = '"Acme Billing" <billing@acme-secure.example>'
    msg["To"] = "user@example.com"
    msg["Subject"] = "Invoice 12345 - URGENT"
    msg["Reply-To"] = "attacker@elsewhere.test"
    msg.set_content("Plain-text fallback.")
    msg.add_alternative(
        '<html><body><p>Open the attached invoice.</p>'
        '<p>Tracking link: <a href="http://attacker.example.com/c2">click</a></p>'
        '</body></html>',
        subtype="html",
    )
    msg.add_attachment(pdf_bytes, maintype="application", subtype="pdf",
                       filename="invoice.pdf")
    out.write_bytes(bytes(msg))


def test_eml_mode_parses_and_extracts(AttachmentAnalyzer, tmp_path):
    """_parse_eml extracts attachments + URLs from a synthetic .eml."""
    pikepdf = pytest.importorskip("pikepdf")  # noqa: F841 env gate

    repo_root = Path(__file__).resolve().parent.parent
    src_pdf = repo_root / "test_pdfs" / "test_javascript.pdf"
    if not src_pdf.exists():
        pytest.skip(f"missing fixture PDF: {src_pdf}")

    email_dir = tmp_path / "email_eml"
    email_dir.mkdir()
    eml = email_dir / "message.eml"
    _build_eml(eml, src_pdf.read_bytes())

    analyzer = AttachmentAnalyzer(str(tmp_path), mode="eml")

    # --- _find_eml_file ---
    found = analyzer._find_eml_file(email_dir)
    assert found == eml

    # --- _parse_eml ---
    msg, body, attached = analyzer._parse_eml(eml, email_dir)
    assert msg is not None
    assert body and "Open the attached invoice." in body
    assert attached == email_dir / "attached_files"
    assert (attached / "invoice.pdf").exists()

    # body URL extracted to link.txt for downstream domain_intel
    link_file = email_dir / "link.txt"
    assert link_file.exists()
    assert "http://attacker.example.com/c2" in link_file.read_text(encoding="utf-8")


def test_eml_mode_attachment_is_analyzed_correctly(AttachmentAnalyzer, tmp_path):
    """After _parse_eml, the extracted PDF runs through analyze_pdf
    and produces the expected verdict + codes."""
    pikepdf = pytest.importorskip("pikepdf")  # noqa: F841 env gate

    repo_root = Path(__file__).resolve().parent.parent
    src_pdf = repo_root / "test_pdfs" / "test_javascript.pdf"
    if not src_pdf.exists():
        pytest.skip(f"missing fixture PDF: {src_pdf}")

    email_dir = tmp_path / "email_eml"
    email_dir.mkdir()
    _build_eml(email_dir / "message.eml", src_pdf.read_bytes())

    analyzer = AttachmentAnalyzer(str(tmp_path), mode="eml")
    _msg, _body, attached = analyzer._parse_eml(email_dir / "message.eml",
                                                  email_dir)
    extracted_pdf = attached / "invoice.pdf"
    assert extracted_pdf.exists()

    result = analyzer.analyze_pdf(extracted_pdf)
    codes = {f.get("code") for f in result["findings"] if f.get("code")}
    assert "PDF.ACTION_JAVASCRIPT" in codes
    assert result["verdict"] in ("suspicious", "malicious")
