"""IOCExtractor unit tests."""

from tools.custom.iocs import IOCExtractor


def test_extract_urls(ioc_extractor: IOCExtractor):
    text = "Visit http://evil.example.com/path?x=1 and https://safe.test/login"
    out = ioc_extractor.extract(text)
    assert "http://evil.example.com/path?x=1" in out["urls"]
    assert "https://safe.test/login" in out["urls"]


def test_extract_ipv4(ioc_extractor: IOCExtractor):
    text = "callback to 198.51.100.42 and 10.0.0.1, but not 999.1.2.3"
    ips = ioc_extractor.extract(text)["ips"]
    assert "198.51.100.42" in ips
    assert "10.0.0.1" in ips
    assert "999.1.2.3" not in ips


def test_extract_hashes(ioc_extractor: IOCExtractor):
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    out = ioc_extractor.extract(f"hashes: {md5} and {sha256}")
    assert md5 in out["hashes_md5"]
    assert sha256 in out["hashes_sha256"]


def test_extract_registry(ioc_extractor: IOCExtractor):
    text = r"key=HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
    keys = ioc_extractor.extract(text)["registry_keys"]
    assert any(k.startswith("HKLM") for k in keys)


def test_domain_blocklist_excludes_filenames(ioc_extractor: IOCExtractor):
    out = ioc_extractor.extract("filename is invoice.pdf and report.docx")
    # invoice.pdf and report.docx should NOT be reported as domains
    assert "invoice.pdf" not in out["domains"]
    assert "report.docx" not in out["domains"]


def test_deobfuscate_chr(ioc_extractor: IOCExtractor):
    # VBA: Chr(72) & Chr(105)  ->  "H" & "i"  ->  "Hi"
    obf = "x = Chr(72) & Chr(105)"
    out = ioc_extractor.deobfuscate_string(obf)
    assert "H" in out and "i" in out


def test_deobfuscate_concat(ioc_extractor: IOCExtractor):
    obf = '"http://" + "evil.com" + "/path"'
    out = ioc_extractor.deobfuscate_string(obf)
    assert "http://evil.com/path" in out


def test_deobfuscate_strreverse(ioc_extractor: IOCExtractor):
    obf = 'StrReverse("moc.live//:ptth")'
    out = ioc_extractor.deobfuscate_string(obf)
    assert "http://evil.com" in out


def test_deobfuscate_b64(ioc_extractor: IOCExtractor):
    # base64 of "http://evil.example.com/x" plus padding
    import base64
    b64 = base64.b64encode(b"http://evil.example.com/payload").decode()
    out = ioc_extractor.deobfuscate_string(f"data = {b64}")
    assert "http://evil.example.com/payload" in out


def test_empty_input(ioc_extractor: IOCExtractor):
    out = ioc_extractor.extract("")
    assert all(v == [] for v in out.values())


def test_union_dedupes(ioc_extractor: IOCExtractor):
    a = {"urls": ["http://a/", "http://b/"], "ips": ["1.1.1.1"]}
    b = {"urls": ["http://b/", "http://c/"], "ips": ["1.1.1.1", "2.2.2.2"]}
    merged = IOCExtractor.union(a, b)
    assert merged["urls"] == ["http://a/", "http://b/", "http://c/"]
    assert merged["ips"] == ["1.1.1.1", "2.2.2.2"]
