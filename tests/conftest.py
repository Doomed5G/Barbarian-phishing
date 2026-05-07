"""Shared pytest fixtures for tools/custom analyzers."""

import sys
from pathlib import Path

import pytest

# Make project root importable so `from tools.custom import ...` works
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def project_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def test_pdfs_dir(project_root: Path) -> Path:
    return project_root / "test_pdfs"


@pytest.fixture()
def ioc_extractor():
    from tools.custom.iocs import IOCExtractor
    return IOCExtractor()


@pytest.fixture()
def score_engine():
    from tools.custom.scoring import ScoreEngine
    return ScoreEngine()


@pytest.fixture()
def pdf_analyzer():
    pikepdf = pytest.importorskip("pikepdf")  # noqa: F841 env gate
    from tools.custom.pdf_analyzer import PDFAnalyzer
    return PDFAnalyzer()
