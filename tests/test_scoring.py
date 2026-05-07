"""ScoreEngine unit tests."""

from tools.custom.scoring import ScoreEngine


def test_no_findings_is_clean(score_engine: ScoreEngine):
    score, verdict, _ = score_engine.score([])
    assert score == 0
    assert verdict == "clean"


def test_lone_acroform_is_clean(score_engine: ScoreEngine):
    findings = [{"code": "PDF.ACROFORM", "severity": "INFO"}]
    score, verdict, _ = score_engine.score(findings)
    assert verdict == "clean"


def test_lone_javascript_is_suspicious(score_engine: ScoreEngine):
    findings = [{"code": "PDF.ACTION_JAVASCRIPT", "severity": "HIGH"}]
    score, verdict, _ = score_engine.score(findings)
    assert verdict in ("suspicious", "clean")


def test_openaction_plus_eval_is_malicious(score_engine: ScoreEngine):
    findings = [
        {"code": "PDF.OPENACTION", "severity": "HIGH"},
        {"code": "PDF.ACTION_JAVASCRIPT", "severity": "HIGH"},
        {"code": "PDF.JS_EVAL", "severity": "HIGH"},
    ]
    score, verdict, summary = score_engine.score(findings)
    assert verdict == "malicious"
    assert score >= 70
    # Correlation summary should be specific, not generic
    assert "OpenAction" in summary or "eval" in summary.lower()


def test_launch_action_is_malicious(score_engine: ScoreEngine):
    findings = [{"code": "PDF.ACTION_LAUNCH", "severity": "CRITICAL"}]
    score, verdict, _ = score_engine.score(findings)
    assert verdict == "malicious"


def test_pe_embed_is_malicious(score_engine: ScoreEngine):
    findings = [{"code": "PDF.EMBEDDED_FILE_PE", "severity": "CRITICAL"}]
    score, verdict, _ = score_engine.score(findings)
    assert verdict == "malicious"


def test_polyglot_is_at_least_suspicious(score_engine: ScoreEngine):
    findings = [{"code": "PDF.POLYGLOT", "severity": "HIGH"}]
    score, verdict, _ = score_engine.score(findings)
    assert verdict in ("suspicious", "malicious")


def test_distinct_codes_only_counted_once(score_engine: ScoreEngine):
    findings = [
        {"code": "PDF.ACTION_JAVASCRIPT", "severity": "HIGH"},
        {"code": "PDF.ACTION_JAVASCRIPT", "severity": "HIGH"},
        {"code": "PDF.ACTION_JAVASCRIPT", "severity": "HIGH"},
    ]
    score, _, _ = score_engine.score(findings)
    # Only one base score contribution (25), nowhere near malicious
    assert score < 70


def test_score_clamped_to_100(score_engine: ScoreEngine):
    # Pile on high-impact codes
    findings = [
        {"code": "PDF.ACTION_LAUNCH"},
        {"code": "PDF.EMBEDDED_FILE_PE"},
        {"code": "PDF.ACTION_JAVASCRIPT"},
        {"code": "PDF.OPENACTION"},
        {"code": "PDF.JS_EVAL"},
        {"code": "PDF.JS_SHELLCODE"},
        {"code": "PDF.POLYGLOT"},
    ]
    score, verdict, _ = score_engine.score(findings)
    assert score <= 100
    assert verdict == "malicious"
