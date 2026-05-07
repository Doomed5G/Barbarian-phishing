#!/usr/bin/env python3
"""
Verdict / score engine for analyzer findings.

Each finding carries a stable `code` (e.g. 'PDF.JS_OPENACTION'). The engine
sums BASE_SCORES, applies CORRELATION bonuses when sets of codes co-occur,
clamps to 0..100, and maps to a verdict label and one-line analyst summary.

Phase 1 ships PDF rules + EMAIL.PASSWORD_HINT correlation.
Phase 2 adds OFFICE.* rules and the OFFICE.ENCRYPTED + EMAIL.PASSWORD_HINT
correlation.
"""

from typing import Dict, List, Tuple


# Per-code base contribution to the file score (0..100)
BASE_SCORES: Dict[str, int] = {
    # ----- PDF: actions -----
    "PDF.ACTION_JAVASCRIPT":      25,
    "PDF.ACTION_LAUNCH":          70,
    "PDF.ACTION_SUBMITFORM":      25,
    "PDF.ACTION_IMPORTDATA":      30,
    "PDF.ACTION_GOTOR":           15,
    "PDF.ACTION_GOTOE":           20,
    "PDF.ACTION_URI":              5,
    "PDF.ACTION_NAMED":            5,
    "PDF.ACTION_HIDE":            10,
    "PDF.ACTION_RICHMEDIAEXECUTE": 35,

    # ----- PDF: triggers -----
    "PDF.OPENACTION":             20,
    "PDF.AUTOACTION":             25,  # /AA on catalog or page

    # ----- PDF: javascript content scan -----
    "PDF.JS_EVAL":                25,
    "PDF.JS_UNESCAPE":            15,
    "PDF.JS_FROMCHARCODE":        15,
    "PDF.JS_LAUNCH_URL":          20,
    "PDF.JS_LONG_LITERAL":        10,
    "PDF.JS_SHELLCODE":           45,
    "PDF.JS_CVE_COLLAB_EMAIL":    50,  # CVE-2007-5659
    "PDF.JS_CVE_COLLAB_GETICON":  50,  # CVE-2009-0927
    "PDF.JS_CVE_GETANNOTS":       50,  # CVE-2009-1492
    "PDF.JS_CVE_NEWPLAYER":       50,  # CVE-2009-4324
    "PDF.JS_UTIL_PRINTF":         35,

    # ----- PDF: structure / forms -----
    "PDF.ACROFORM":                2,
    "PDF.XFA":                    10,
    "PDF.XFA_SCRIPT":             40,
    "PDF.EMBEDDED_FILE":          15,
    "PDF.EMBEDDED_FILE_PE":       75,
    "PDF.EMBEDDED_FILE_SCRIPT":   55,
    "PDF.RICHMEDIA":              25,

    # ----- PDF: stream / filter audit -----
    "PDF.JBIG2DECODE":            20,
    "PDF.ASCII85_CHAINED":        15,
    "PDF.OBJSTM_HIDES_JS":        35,

    # ----- PDF: encryption -----
    "PDF.ENCRYPTED":              25,
    "PDF.ENCRYPTED_WEAK_PASS":    40,

    # ----- PDF: byte-level oddities -----
    "PDF.POLYGLOT":               55,
    "PDF.SIZE_MISMATCH":          15,
    "PDF.MALFORMED":              25,

    # ----- Office: macros -----
    "OFFICE.VBA_PRESENT":         15,
    "OFFICE.VBA_AUTOEXEC":        30,
    "OFFICE.VBA_SUSPICIOUS":      15,
    "OFFICE.VBA_SHELL":           35,
    "OFFICE.VBA_DOWNLOAD":        35,
    "OFFICE.VBA_OBFUSCATED":      20,
    "OFFICE.VBA_IOC_URL":         10,
    "OFFICE.VBA_IOC_IP":          10,
    "OFFICE.AUTOEXEC":            25,  # generic auto-exec marker (DDE etc.)

    # ----- Office: OOXML structural -----
    "OFFICE.DDE":                 35,
    "OFFICE.DDEAUTO":             50,
    "OFFICE.EXTERNAL_TEMPLATE":   45,  # CVE-2017-0199 marker
    "OFFICE.EXTERNAL_HTTP":       15,
    "OFFICE.EXTERNAL_REMOTE_IMG": 10,
    "OFFICE.EMBEDDED_OLE":        15,
    "OFFICE.EMBEDDED_OLE_PE":     70,

    # ----- Office: RTF -----
    "OFFICE.RTF_OLE_EQUATION":    65,  # CVE-2017-11882
    "OFFICE.RTF_OLE_LINK":        50,  # CVE-2017-0199
    "OFFICE.RTF_OLE_PACKAGE":     35,
    "OFFICE.RTF_OLE_PACKAGE_PE":  75,

    # ----- Office: XLM (Excel 4.0) macros -----
    "OFFICE.XLM_MACROS":          30,
    "OFFICE.XLM_AUTOEXEC":        45,

    # ----- Office: encryption -----
    "OFFICE.ENCRYPTED":           25,
    "OFFICE.ENCRYPTED_WEAK_PASS": 40,

    # ----- Office: parser errors / odd files -----
    "OFFICE.MALFORMED":           20,

    # ----- email-level signal (set by main script when body has hint) -----
    "EMAIL.PASSWORD_HINT":         5,
}


# Correlations: when ALL codes in `required` are present, add `bonus` and
# emit `summary` as the analyst-readable rationale.
CORRELATIONS: List[Tuple[List[str], int, str]] = [
    (["PDF.OPENACTION", "PDF.ACTION_JAVASCRIPT"], 15,
     "PDF auto-runs JavaScript on open"),

    (["PDF.OPENACTION", "PDF.ACTION_JAVASCRIPT", "PDF.JS_EVAL"], 25,
     "PDF auto-runs eval()-based JavaScript on open"),

    (["PDF.OPENACTION", "PDF.ACTION_JAVASCRIPT", "PDF.JS_SHELLCODE"], 30,
     "PDF auto-runs JavaScript containing shellcode-style markers"),

    (["PDF.ACROFORM", "PDF.ACTION_SUBMITFORM"], 15,
     "PDF form submits to remote endpoint"),

    (["PDF.ENCRYPTED", "EMAIL.PASSWORD_HINT"], 20,
     "Password-protected PDF with password hinted in email body (classic phish)"),

    # Phase 2 (Office) listed here so engine is forward-compatible.
    (["OFFICE.VBA_AUTOEXEC", "OFFICE.VBA_SHELL"], 30,
     "Auto-executing macro spawns shell"),

    (["OFFICE.VBA_AUTOEXEC", "OFFICE.VBA_DOWNLOAD"], 30,
     "Auto-executing macro downloads payload"),

    (["OFFICE.ENCRYPTED", "EMAIL.PASSWORD_HINT"], 20,
     "Password-protected Office doc with password hinted in body"),

    (["OFFICE.DDE", "OFFICE.AUTOEXEC"], 25,
     "Document uses DDE auto-execution"),

    (["OFFICE.EXTERNAL_TEMPLATE", "OFFICE.EXTERNAL_HTTP"], 25,
     "Document loads remote template (CVE-2017-0199 family)"),
]


# Verdict thresholds
SCORE_MALICIOUS = 70
SCORE_SUSPICIOUS = 30


class ScoreEngine:
    """Score a list of findings, return (score, verdict, summary)."""

    def __init__(
        self,
        base_scores: Dict[str, int] = None,
        correlations: List[Tuple[List[str], int, str]] = None,
    ):
        self.base_scores = base_scores if base_scores is not None else BASE_SCORES
        self.correlations = correlations if correlations is not None else CORRELATIONS

    def score(self, findings: List[Dict]) -> Tuple[int, str, str]:
        """
        Returns (score 0..100, verdict 'clean'|'suspicious'|'malicious',
                 one-line summary).
        """
        codes = [f.get("code") for f in findings if f.get("code")]
        code_set = set(codes)

        # Sum bases count distinct codes only (don't multi-count the same
        # rule firing N times on the same file)
        total = sum(self.base_scores.get(c, 0) for c in code_set)

        # Correlation bonuses + collect rationales.
        # Process most-specific rules first (longest required-list) so the
        # leading rationale is the most informative.
        rationales: List[str] = []
        ordered = sorted(self.correlations, key=lambda c: -len(c[0]))
        for required, bonus, summary in ordered:
            if all(r in code_set for r in required):
                total += bonus
                rationales.append(summary)

        score = max(0, min(100, total))
        verdict = self._verdict(score)
        summary = self._summary(verdict, score, rationales, findings)
        return score, verdict, summary

    @staticmethod
    def _verdict(score: int) -> str:
        if score >= SCORE_MALICIOUS:
            return "malicious"
        if score >= SCORE_SUSPICIOUS:
            return "suspicious"
        return "clean"

    @staticmethod
    def _summary(
        verdict: str,
        score: int,
        rationales: List[str],
        findings: List[Dict],
    ) -> str:
        if verdict == "clean":
            return f"No correlated indicators (score {score}/100)."
        if rationales:
            head = rationales[0]
            extra = f" (+{len(rationales) - 1} more)" if len(rationales) > 1 else ""
            return f"{head}{extra}."
        # No correlation fired but base score got us over threshold
        # surface the highest-severity finding's message.
        ranking = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        worst = max(
            findings,
            key=lambda f: ranking.get(f.get("severity", "INFO"), 0),
            default=None,
        )
        if worst and worst.get("message"):
            return worst["message"]
        return f"{verdict.title()} (score {score}/100)."
