#!/usr/bin/env python3
"""
Shared IOC extractor and string deobfuscator.

Used by pdf_analyzer (decoded JS), office_analyzer (deobfuscated VBA),
attachment_analyzer (script bodies), and any future module that needs to
pull URLs / IPs / hashes / paths out of free-form text.
"""

import base64
import binascii
import re
from typing import Dict, List


_URL_RE = re.compile(
    r"""(?ix)
    \b
    (?:https?|ftp|file)://
    [^\s<>"'`)\]\}]+
    """
)

_IPV4_RE = re.compile(
    r"""(?x)
    \b
    (?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])
    (?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}
    \b
    """
)

_DOMAIN_RE = re.compile(
    r"""(?ix)
    \b
    (?=[a-z0-9-]{1,63}\.)
    (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
    [a-z]{2,24}
    \b
    """
)

_EMAIL_RE = re.compile(
    r"""(?ix)
    \b
    [a-z0-9._%+-]+ @ [a-z0-9.-]+ \. [a-z]{2,24}
    \b
    """
)

_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

_REGISTRY_RE = re.compile(
    r"""(?ix)
    \b
    (?:HKLM|HKCU|HKCR|HKU|HKCC
       |HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT
       |HKEY_USERS|HKEY_CURRENT_CONFIG)
    \\[^\s"']{2,200}
    """
)

_PATH_RE = re.compile(
    r"""(?ix)
    (?:
        [a-z]:\\[^\s"'<>|?*]{2,200}
        |
        \\\\[a-z0-9_.-]+\\[^\s"'<>|?*]{2,200}
        |
        /(?:tmp|var|home|usr|opt|etc)/[^\s"'<>|?*]{2,200}
    )
    """
)

_CMDLINE_FLAG_RE = re.compile(r"(?:^|\s)(-{1,2}[a-zA-Z][\w-]{1,30})\b")

# False-positive-prone domain TLDs we never want to surface
_DOMAIN_TLD_BLOCKLIST = {
    "png", "jpg", "jpeg", "gif", "bmp", "tiff", "webp",
    "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm",
    "ppt", "pptx", "pptm", "rtf",
    "exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "js",
    "txt", "tmp", "log", "zip", "rar", "tar", "gz", "7z",
    "lnk", "html", "htm", "xml",
}


class IOCExtractor:
    """Extract URLs, IPs, hashes, registry keys, paths from free-form text."""

    def extract(self, text: str) -> Dict[str, List[str]]:
        if not text:
            return self._empty()
        return {
            "urls":          self._unique(_URL_RE.findall(text)),
            "ips":           self._unique(_IPV4_RE.findall(text)),
            "domains":       self._extract_domains(text),
            "emails":        self._unique(_EMAIL_RE.findall(text)),
            "hashes_md5":    self._unique(_MD5_RE.findall(text)),
            "hashes_sha1":   self._unique(_SHA1_RE.findall(text)),
            "hashes_sha256": self._unique(_SHA256_RE.findall(text)),
            "registry_keys": self._unique(_REGISTRY_RE.findall(text)),
            "paths":         self._unique(_PATH_RE.findall(text)),
            "cmdline_flags": self._unique(_CMDLINE_FLAG_RE.findall(text)),
        }

    def deobfuscate_string(self, text: str) -> str:
        """Best-effort string deobfuscation VBA / JS friendly.

        Applied passes (in order):
            * VBA Chr(N) / ChrW(N) -> char
            * VBA & / + string concat that produces "ab" + "cd" -> "abcd"
            * StrReverse("...") -> reversed literal
            * Hex literal &H?? sequences -> chars
            * Try Base64 decode of long contiguous runs (>= 24 chars)
        Caller still gets the original text appended so regexes can hit
        either form.
        """
        if not text:
            return text
        out = text
        out = self._expand_chr(out)
        out = self._collapse_concat(out)
        out = self._reverse_strreverse(out)
        out = self._expand_hex_literals(out)
        out += "\n" + self._try_b64_decode(out)
        return out

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    @staticmethod
    def _empty() -> Dict[str, List[str]]:
        return {k: [] for k in (
            "urls", "ips", "domains", "emails",
            "hashes_md5", "hashes_sha1", "hashes_sha256",
            "registry_keys", "paths", "cmdline_flags",
        )}

    @staticmethod
    def _unique(items: List[str]) -> List[str]:
        seen, out = set(), []
        for it in items:
            it_norm = it.rstrip(".,;:!?)\"']>")
            if it_norm and it_norm not in seen:
                seen.add(it_norm)
                out.append(it_norm)
        return out

    def _extract_domains(self, text: str) -> List[str]:
        raw = _DOMAIN_RE.findall(text)
        keep = []
        for d in raw:
            tld = d.rsplit(".", 1)[-1].lower()
            if tld in _DOMAIN_TLD_BLOCKLIST:
                continue
            keep.append(d)
        return self._unique(keep)

    @staticmethod
    def _expand_chr(text: str) -> str:
        def sub(m: "re.Match") -> str:
            try:
                n = int(m.group(1))
                return chr(n) if 0 <= n < 0x110000 else m.group(0)
            except (ValueError, OverflowError):
                return m.group(0)
        return re.sub(r"(?i)\bChrW?\(\s*(\d{1,7})\s*\)", sub, text)

    @staticmethod
    def _collapse_concat(text: str) -> str:
        # "ab" + "cd"  /  "ab" & "cd"  -> "abcd"
        prev = None
        cur = text
        for _ in range(8):
            if cur == prev:
                break
            prev = cur
            cur = re.sub(r'"([^"\n]*)"\s*[&+]\s*"([^"\n]*)"', r'"\1\2"', cur)
        return cur

    @staticmethod
    def _reverse_strreverse(text: str) -> str:
        return re.sub(
            r'(?i)StrReverse\(\s*"([^"\n]{1,2048})"\s*\)',
            lambda m: '"' + m.group(1)[::-1] + '"',
            text,
        )

    @staticmethod
    def _expand_hex_literals(text: str) -> str:
        # VBA hex literal: &H41 -> 'A'
        def sub(m: "re.Match") -> str:
            try:
                n = int(m.group(1), 16)
                return chr(n) if 0 <= n < 0x110000 else m.group(0)
            except (ValueError, OverflowError):
                return m.group(0)
        return re.sub(r"&H([0-9A-Fa-f]{1,6})\b", sub, text)

    @staticmethod
    def _try_b64_decode(text: str) -> str:
        decoded_pieces = []
        for m in re.finditer(r"[A-Za-z0-9+/]{24,}={0,2}", text):
            chunk = m.group(0)
            try:
                raw = base64.b64decode(chunk, validate=True)
            except (binascii.Error, ValueError):
                continue
            try:
                as_text = raw.decode("utf-8", errors="ignore")
            except Exception:
                continue
            if sum(c.isprintable() for c in as_text) >= 0.8 * len(as_text):
                decoded_pieces.append(as_text)
        return "\n".join(decoded_pieces)

    # ------------------------------------------------------------------
    # convenience: union dedupe across many extracts
    # ------------------------------------------------------------------

    @staticmethod
    def union(*ioc_dicts: Dict[str, List[str]]) -> Dict[str, List[str]]:
        merged: Dict[str, List[str]] = {}
        for d in ioc_dicts:
            for k, vs in (d or {}).items():
                bucket = merged.setdefault(k, [])
                seen = set(bucket)
                for v in vs:
                    if v not in seen:
                        seen.add(v)
                        bucket.append(v)
        return merged
