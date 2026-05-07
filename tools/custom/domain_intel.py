"""
Domain Intelligence Tool
Analyzes domains extracted from email URLs for reputation and suspicious indicators.
"""

import re
import ssl
import socket
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DomainIntelAnalyzer:
    """Analyzes domains for reputation, age, DNS, SSL, and homograph attacks."""

    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq',
        '.top', '.xyz', '.buzz', '.rest', '.surf',
        '.click', '.link', '.work', '.date', '.racing',
        '.download', '.win', '.bid', '.stream'
    ]

    HOMOGRAPH_MAP = {
        '\u0430': 'a', '\u0435': 'e', '\u043e': 'o',
        '\u0440': 'p', '\u0441': 'c', '\u0443': 'y',
        '\u0456': 'i', '\u04bb': 'h', '\u0501': 'd',
        '\u051b': 'q', '\u0455': 's', '\u0578': 'n',
    }

    KNOWN_BRANDS = [
        'paypal', 'google', 'microsoft', 'apple', 'amazon',
        'facebook', 'netflix', 'linkedin', 'dropbox', 'bank',
        'chase', 'wellsfargo', 'citibank', 'outlook', 'office365',
        'instagram', 'twitter', 'github', 'adobe', 'zoom',
    ]

    def __init__(self):
        self._cache = {}

    def analyze(self, urls: List[str]) -> Dict:
        """Analyze all unique domains from the provided URLs."""
        result = {
            'tool_name': 'Domain Intelligence',
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'tools_used': [],
            'domains': {}
        }

        # Extract unique domains
        domains = set()
        for url in urls:
            domain = self._extract_domain(url)
            if domain:
                domains.add(domain)

        if not domains:
            result['findings'].append({
                'severity': 'INFO',
                'category': 'No Domains',
                'message': 'No valid domains found in URLs',
                'details': ''
            })
            return result

        # Analyze each domain (limit to 20)
        for domain in list(domains)[:20]:
            if domain in self._cache:
                domain_data = self._cache[domain]
            else:
                domain_data = self._analyze_domain(domain)
                self._cache[domain] = domain_data

            result['domains'][domain] = domain_data.get('data', {})
            result['findings'].extend(domain_data.get('findings', []))

        # Track tools used
        tools = []
        if WHOIS_AVAILABLE:
            tools.append({'name': 'WHOIS Lookup', 'status': 'success', 'type': 'custom', 'timestamp': datetime.now().isoformat()})
        else:
            tools.append({'name': 'WHOIS Lookup', 'status': 'unavailable', 'type': 'custom', 'timestamp': datetime.now().isoformat()})

        if DNS_AVAILABLE:
            tools.append({'name': 'DNS Resolver', 'status': 'success', 'type': 'custom', 'timestamp': datetime.now().isoformat()})
        else:
            tools.append({'name': 'DNS Resolver', 'status': 'unavailable', 'type': 'custom', 'timestamp': datetime.now().isoformat()})

        tools.append({'name': 'SSL Checker', 'status': 'success', 'type': 'custom', 'timestamp': datetime.now().isoformat()})
        result['tools_used'] = tools

        return result

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            # Remove port if present
            if ':' in netloc:
                netloc = netloc.split(':')[0]
            return netloc if netloc else None
        except Exception:
            return None

    def _analyze_domain(self, domain: str) -> Dict:
        """Run all checks on a single domain."""
        data = {'domain': domain}
        findings = []

        # Homograph check (no network needed)
        findings.extend(self._check_homograph(domain))

        # Suspicious TLD check (no network needed)
        findings.extend(self._check_suspicious_tld(domain))

        # WHOIS lookup
        if WHOIS_AVAILABLE:
            whois_result = self._whois_lookup(domain)
            data['whois'] = whois_result.get('data', {})
            findings.extend(whois_result.get('findings', []))

        # DNS lookup
        if DNS_AVAILABLE:
            dns_result = self._dns_lookup(domain)
            data['dns'] = dns_result.get('data', {})
            findings.extend(dns_result.get('findings', []))

        # SSL check
        ssl_result = self._ssl_check(domain)
        data['ssl'] = ssl_result.get('data', {})
        findings.extend(ssl_result.get('findings', []))

        return {'data': data, 'findings': findings}

    def _whois_lookup(self, domain: str) -> Dict:
        """WHOIS lookup for domain age and registration info."""
        findings = []
        data = {}
        try:
            w = whois.whois(domain)
            data['registrar'] = str(w.registrar or 'Unknown')
            data['creation_date'] = str(w.creation_date) if w.creation_date else 'Unknown'
            data['expiration_date'] = str(w.expiration_date) if w.expiration_date else 'Unknown'

            # Domain age check
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation and isinstance(creation, datetime):
                age_days = (datetime.now() - creation).days
                data['age_days'] = age_days
                if age_days < 30:
                    findings.append({
                        'severity': 'HIGH',
                        'category': 'Newly Registered Domain',
                        'message': f'Domain "{domain}" registered only {age_days} days ago',
                        'details': f'Registrar: {data["registrar"]}, Created: {data["creation_date"]}'
                    })
                elif age_days < 90:
                    findings.append({
                        'severity': 'MEDIUM',
                        'category': 'Young Domain',
                        'message': f'Domain "{domain}" registered {age_days} days ago',
                        'details': f'Registrar: {data["registrar"]}'
                    })

        except Exception as e:
            data['error'] = str(e)[:200]
            findings.append({
                'severity': 'MEDIUM',
                'category': 'WHOIS Lookup Failed',
                'message': f'Could not retrieve WHOIS data for {domain}',
                'details': str(e)[:200]
            })

        return {'data': data, 'findings': findings}

    def _dns_lookup(self, domain: str) -> Dict:
        """DNS record lookup."""
        findings = []
        records = {}

        for rtype in ['A', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=10)
                records[rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                records[rtype] = []
            except Exception:
                records[rtype] = []

        # Check for NXDOMAIN (domain doesn't exist)
        if not records.get('A') and not records.get('MX'):
            findings.append({
                'severity': 'HIGH',
                'category': 'Domain Not Resolving',
                'message': f'Domain "{domain}" has no A or MX records',
                'details': 'Domain may not exist or DNS is misconfigured'
            })

        # Check SPF in TXT records
        txt_records = records.get('TXT', [])
        spf_records = [r for r in txt_records if 'v=spf1' in r]
        if not spf_records and records.get('MX'):
            findings.append({
                'severity': 'MEDIUM',
                'category': 'No SPF Record',
                'message': f'Domain "{domain}" has no SPF record but has MX records',
                'details': 'Sender domain does not have SPF configured'
            })

        return {'data': records, 'findings': findings}

    def _ssl_check(self, domain: str) -> Dict:
        """SSL certificate inspection."""
        findings = []
        cert_data = {}

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cert_data['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    cert_data['subject'] = dict(x[0] for x in cert.get('subject', []))
                    cert_data['notAfter'] = cert.get('notAfter', '')
                    cert_data['notBefore'] = cert.get('notBefore', '')

                    # Check expiry
                    try:
                        expiry = ssl.cert_time_to_seconds(cert['notAfter'])
                        if expiry < time.time():
                            findings.append({
                                'severity': 'HIGH',
                                'category': 'Expired Certificate',
                                'message': f'SSL certificate for "{domain}" has expired',
                                'details': f'Expired: {cert["notAfter"]}'
                            })
                    except Exception:
                        pass

                    # Check domain match
                    san = cert.get('subjectAltName', [])
                    cert_domains = [val for typ, val in san if typ == 'DNS']
                    if cert_domains and not any(self._domain_matches(domain, cd) for cd in cert_domains):
                        findings.append({
                            'severity': 'HIGH',
                            'category': 'Certificate Domain Mismatch',
                            'message': f'SSL certificate does not match domain "{domain}"',
                            'details': f'Certificate covers: {", ".join(cert_domains[:5])}'
                        })

                    # Self-signed check
                    issuer_cn = cert_data.get('issuer', {}).get('commonName', '')
                    subject_cn = cert_data.get('subject', {}).get('commonName', '')
                    if issuer_cn and subject_cn and issuer_cn == subject_cn:
                        findings.append({
                            'severity': 'MEDIUM',
                            'category': 'Self-Signed Certificate',
                            'message': f'Domain "{domain}" uses a self-signed certificate',
                            'details': f'Issuer and Subject are both: {issuer_cn}'
                        })

        except ssl.SSLCertVerificationError as e:
            findings.append({
                'severity': 'HIGH',
                'category': 'SSL Verification Failed',
                'message': f'SSL verification failed for "{domain}"',
                'details': str(e)[:200]
            })
        except (socket.timeout, ConnectionRefusedError, OSError):
            cert_data['status'] = 'not_available'

        return {'data': cert_data, 'findings': findings}

    def _domain_matches(self, domain: str, cert_domain: str) -> bool:
        """Check if a domain matches a certificate domain (supports wildcards)."""
        if cert_domain.startswith('*.'):
            return domain.endswith(cert_domain[1:]) or domain == cert_domain[2:]
        return domain == cert_domain

    def _check_homograph(self, domain: str) -> List[Dict]:
        """Detect IDN homograph attacks."""
        findings = []
        has_non_ascii = any(ord(c) > 127 for c in domain)
        if has_non_ascii:
            findings.append({
                'severity': 'HIGH',
                'category': 'IDN Homograph Attack',
                'message': f'Domain contains non-ASCII characters: {domain}',
                'details': 'Possible visual spoofing using international characters'
            })
            # Check for brand impersonation
            ascii_equiv = ''.join(self.HOMOGRAPH_MAP.get(c, c) for c in domain)
            for brand in self.KNOWN_BRANDS:
                if brand in ascii_equiv.lower():
                    findings.append({
                        'severity': 'CRITICAL',
                        'category': 'Brand Impersonation',
                        'message': f'Domain mimics "{brand}": {domain} -> {ascii_equiv}',
                        'details': 'IDN homograph attack targeting known brand'
                    })
        return findings

    def _check_suspicious_tld(self, domain: str) -> List[Dict]:
        """Flag known-problematic TLDs."""
        findings = []
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                findings.append({
                    'severity': 'MEDIUM',
                    'category': 'Suspicious TLD',
                    'message': f'Domain "{domain}" uses frequently-abused TLD: {tld}',
                    'details': 'This TLD is commonly associated with phishing and malware'
                })
                break
        return findings
