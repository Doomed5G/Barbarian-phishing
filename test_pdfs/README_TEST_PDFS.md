# PDF Test Files for Barbarian Phishing

This directory contains test PDF files designed to trigger various security checks in the `barbarian-phishing.py` script. These files are for **TESTING PURPOSES ONLY** and should be used in isolated environments.

## Purpose

These PDFs contain suspicious elements that security tools should detect. They are safe test files that mimic patterns found in malicious PDFs without containing actual exploits.

## Test Files Overview

### 1. test_clean.pdf
**Status:** ✅ CLEAN
**Purpose:** Baseline test file with no suspicious elements
**Expected Result:** Should pass all security checks
**Contains:**
- Simple text content
- No JavaScript, actions, or embedded files
- Should be marked as "clean" by the analyzer

---

### 2. test_javascript.pdf
**Status:** ⚠️ HIGH RISK
**Purpose:** Tests detection of JavaScript in PDFs
**Expected Result:** Should trigger HIGH severity finding
**Contains:**
- `/JavaScript` element
- `/OpenAction` that executes JavaScript on document open
- `app.alert()` function call

**Checks Triggered:**
- `/JS` detection
- `/JavaScript` detection
- `/OpenAction` detection

---

### 3. test_openaction.pdf
**Status:** ⚠️ HIGH RISK
**Purpose:** Tests detection of auto-action elements
**Expected Result:** Should trigger HIGH severity finding
**Contains:**
- `/AA` (Additional Actions) at document and page level
- `/OpenAction` with JavaScript
- Auto-execute on page open

**Checks Triggered:**
- `/AA` detection
- `/OpenAction` detection
- `/JavaScript` detection

---

### 4. test_launch.pdf
**Status:** ⚠️ CRITICAL
**Purpose:** Tests detection of Launch actions (can execute programs)
**Expected Result:** Should trigger HIGH/CRITICAL severity finding
**Contains:**
- `/Launch` action
- Reference to `calc.exe` (system executable)
- Command-line parameters

**Checks Triggered:**
- `/Launch` detection
- Potential code execution risk

---

### 5. test_embeddedfile.pdf
**Status:** ⚠️ MEDIUM RISK
**Purpose:** Tests detection of embedded files
**Expected Result:** Should trigger MEDIUM severity finding
**Contains:**
- `/EmbeddedFile` object
- Embedded text file within PDF
- File specification structure

**Checks Triggered:**
- `/EmbeddedFile` detection
- Polyglot file possibility

---

### 6. test_acroform.pdf
**Status:** ⚠️ MEDIUM-HIGH RISK
**Purpose:** Tests detection of interactive forms and data submission
**Expected Result:** Should trigger MEDIUM/HIGH severity finding
**Contains:**
- `/AcroForm` structure
- `/SubmitForm` action pointing to external URL
- Form fields with actions

**Checks Triggered:**
- `/AcroForm` detection
- `/SubmitForm` detection
- Potential data exfiltration risk

---

### 7. test_richmedia.pdf
**Status:** ⚠️ HIGH RISK
**Purpose:** Tests detection of rich media content (Flash/multimedia)
**Expected Result:** Should trigger HIGH severity finding
**Contains:**
- `/RichMedia` annotation
- `/RichMediaContent` with embedded Flash reference
- Fake SWF file embedded

**Checks Triggered:**
- `/RichMedia` detection
- Flash content (historically exploitable)
- `/EmbeddedFile` detection

---

### 8. test_gotor_gotoe.pdf
**Status:** ⚠️ MEDIUM-HIGH RISK
**Purpose:** Tests detection of remote/embedded document navigation
**Expected Result:** Should trigger MEDIUM/HIGH severity finding
**Contains:**
- `/GoToR` (Go To Remote) action pointing to external URL
- `/GoToE` (Go To Embedded) action
- Links that navigate to potentially malicious external PDFs

**Checks Triggered:**
- `/GoToR` detection
- `/GoToE` detection
- Remote file access risk

---

### 9. test_objstm.pdf
**Status:** ⚠️ MEDIUM RISK
**Purpose:** Tests detection of compressed object streams (obfuscation)
**Expected Result:** Should trigger MEDIUM severity finding
**Contains:**
- `/ObjStm` (Object Stream)
- Compressed/hidden objects
- JavaScript hidden within object stream

**Checks Triggered:**
- `/ObjStm` detection
- Obfuscation technique
- Hidden JavaScript

---

### 10. test_multiple_threats.pdf
**Status:** 🚨 CRITICAL
**Purpose:** Comprehensive test with multiple suspicious elements
**Expected Result:** Should trigger MULTIPLE HIGH/CRITICAL severity findings
**Contains:**
- JavaScript with shellcode-like patterns
- `/Launch` action to cmd.exe
- `/GoToR` to external URL
- `/SubmitForm` to external server
- `/EmbeddedFile` with executable signature (fake MZ header)
- `/AA` auto-actions
- `/XFA` forms
- Multiple annotations with malicious actions

**Checks Triggered:**
- `/JS`, `/JavaScript`
- `/AA`, `/OpenAction`
- `/Launch`
- `/GoToR`
- `/SubmitForm`
- `/EmbeddedFile`
- `/XFA`
- `/AcroForm`

**This file should trigger the most alerts and be flagged for immediate manual review.**

---

## Usage Instructions

### Running Tests

1. Create a test email folder structure:
```bash
mkdir -p test_emails/email1/attached_files
cp test_pdfs/*.pdf test_emails/email1/attached_files/
```

2. Run the analyzer:
```bash
python barbarian-phishing.py test_emails/
```

3. Review the generated HTML and JSON reports

### Expected Behavior

The analyzer should:
- ✅ Mark `test_clean.pdf` as clean (no findings)
- ⚠️ Flag all other PDFs with appropriate severity levels
- 🚨 Mark `test_multiple_threats.pdf` as CRITICAL with recommendations for manual review
- Generate detailed findings for each suspicious element
- Provide file hashes for all analyzed files
- Create recommendations for high-risk files

### Validation Checklist

Use this checklist to verify the analyzer is working correctly:

- [ ] `test_clean.pdf` passes without warnings
- [ ] `test_javascript.pdf` triggers JavaScript detection
- [ ] `test_openaction.pdf` triggers AA/OpenAction detection
- [ ] `test_launch.pdf` triggers Launch action detection
- [ ] `test_embeddedfile.pdf` triggers EmbeddedFile detection
- [ ] `test_acroform.pdf` triggers AcroForm/SubmitForm detection
- [ ] `test_richmedia.pdf` triggers RichMedia detection
- [ ] `test_gotor_gotoe.pdf` triggers GoToR/GoToE detection
- [ ] `test_objstm.pdf` triggers ObjStm detection
- [ ] `test_multiple_threats.pdf` triggers multiple HIGH/CRITICAL findings
- [ ] All files generate proper MD5/SHA1/SHA256 hashes
- [ ] HTML report displays all findings with severity colors
- [ ] JSON report contains structured data for all findings

## Safety Notes

⚠️ **IMPORTANT:**
- These PDFs contain **test signatures only** - they are NOT actual malware
- Some antivirus software may flag these files due to suspicious patterns
- Use only in isolated test environments
- Do NOT open these files in production PDF readers without sandboxing
- Do NOT distribute these files outside of testing contexts
- The embedded "malicious" patterns are intentionally neutered and safe

## Adding New Tests

To add new test cases:

1. Create a minimal PDF with the suspicious element
2. Document what it tests in this README
3. Add it to the validation checklist
4. Verify it triggers the expected detection

## Tools for Manual Analysis

If you want to manually inspect these PDFs:

- **pdf-parser.py** - Parse PDF structure and search for objects
- **pdfid.py** - Quick overview of suspicious elements
- **pdftool** - Extract and analyze PDF components
- **qpdf** - Decompress and linearize PDFs for inspection

Example:
```bash
python pdf-parser.py --search javascript test_javascript.pdf
python pdfid.py test_multiple_threats.pdf
```

## References

Based on common malicious PDF techniques:
- JavaScript exploitation
- Launch actions for code execution
- Form-based data exfiltration
- Remote file inclusion
- Object stream obfuscation
- Embedded file payloads

## License

These test files are provided for security testing and educational purposes only.
Use responsibly and ethically.

---

**Generated for:** Barbarian Phishing
**Version:** 1.0
**Date:** 2026-02-03
