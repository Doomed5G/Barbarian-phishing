"""
Body Link Analyzer
Analyzes email body HTML for deceptive links, URL mismatches, and phishing patterns.
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse, unquote

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


class BodyLinkAnalyzer:
    """Analyzes email body for deceptive links and phishing indicators."""

    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd',
        'buff.ly', 'ow.ly', 'rebrand.ly', 'short.link', 'tiny.cc',
        'cutt.ly', 'rb.gy', 'shorturl.at', 'shorten.rest',
    ]

    CREDENTIAL_PATHS = [
        '/login', '/signin', '/sign-in', '/verify', '/account',
        '/secure', '/update', '/confirm', '/authenticate',
        '/password', '/reset', '/unlock', '/validate',
    ]

    def analyze(self, email_folder: Path, mode: str = 'normal', eml_body: str = None) -> Dict:
        """Analyze email body for deceptive links."""
        result = {
            'tool_name': 'Body Link Analyzer',
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'tools_used': [],
            'links_analyzed': []
        }

        html_content = None

        if mode == 'eml' and eml_body:
            html_content = eml_body
        elif mode == 'normal':
            body_html = email_folder / 'body.html'
            body_txt = email_folder / 'body.txt'
            if body_html.exists():
                try:
                    html_content = body_html.read_text(encoding='utf-8', errors='ignore')
                except Exception:
                    html_content = body_html.read_text(errors='ignore')
            elif body_txt.exists():
                try:
                    text_content = body_txt.read_text(encoding='utf-8', errors='ignore')
                except Exception:
                    text_content = body_txt.read_text(errors='ignore')
                result['findings'].extend(self._extract_text_urls(text_content))
                result['tools_used'].append({
                    'name': 'Body Link Analyzer',
                    'status': 'success',
                    'type': 'custom',
                    'timestamp': datetime.now().isoformat()
                })
                return result

        if not html_content:
            result['findings'].append({
                'severity': 'INFO',
                'category': 'No Email Body',
                'message': 'No body.html or body.txt found in email folder',
                'details': ''
            })
            result['tools_used'].append({
                'name': 'Body Link Analyzer',
                'status': 'unavailable',
                'type': 'custom',
                'timestamp': datetime.now().isoformat()
            })
            return result

        # Analyze HTML body
        if BS4_AVAILABLE:
            body_findings, links_table = self._analyze_html_body(html_content)
            result['findings'].extend(body_findings)
            result['links_analyzed'] = links_table
        result['findings'].extend(self._extract_text_urls(html_content))

        result['tools_used'].append({
            'name': 'Body Link Analyzer',
            'status': 'success',
            'type': 'custom',
            'timestamp': datetime.now().isoformat()
        })

        return result

    def _analyze_html_body(self, html_content: str):
        """Parse HTML body and check all links for deception.

        Returns:
            Tuple of (findings list, links_analyzed list)
        """
        findings = []
        links_analyzed = []

        try:
            soup = BeautifulSoup(html_content, 'html.parser')
        except Exception:
            return findings, []

        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            display_text = a_tag.get_text(strip=True)
            is_mismatch = False

            # 1. URL mismatch detection - display text looks like a URL but goes elsewhere
            display_urls = re.findall(r'https?://[^\s]+', display_text)
            if display_urls:
                display_url = display_urls[0]
                display_domain = urlparse(display_url).netloc.lower()
                href_domain = urlparse(href).netloc.lower()

                # Remove port numbers for comparison
                display_domain = display_domain.split(':')[0]
                href_domain = href_domain.split(':')[0]

                if display_domain and href_domain and display_domain != href_domain:
                    is_mismatch = True
                    findings.append({
                        'severity': 'CRITICAL',
                        'category': 'URL Mismatch',
                        'message': f'Displayed URL ({display_domain}) does NOT match actual destination ({href_domain})',
                        'details': f'Display text: {display_text[:100]}\nActual href: {href[:100]}'
                    })

            # 2. URL shorteners
            href_domain = urlparse(href).netloc.lower().split(':')[0]
            if href_domain in self.URL_SHORTENERS:
                findings.append({
                    'severity': 'MEDIUM',
                    'category': 'URL Shortener',
                    'message': f'Link uses URL shortener: {href_domain}',
                    'details': f'Display: {display_text[:80]}\nFull URL: {href[:200]}'
                })

            # 3. Homograph in display text
            if display_text and any(ord(c) > 127 for c in display_text):
                findings.append({
                    'severity': 'HIGH',
                    'category': 'Homograph in Display Text',
                    'message': f'Link display text contains non-ASCII characters',
                    'details': f'Display: {display_text[:100]}'
                })

            # 4. JavaScript URI
            if href.lower().strip().startswith('javascript:'):
                findings.append({
                    'severity': 'CRITICAL',
                    'category': 'JavaScript URI',
                    'message': 'Link contains javascript: URI - potential XSS',
                    'details': f'href: {href[:200]}'
                })

            # 5. Data URI
            elif href.lower().strip().startswith('data:'):
                findings.append({
                    'severity': 'HIGH',
                    'category': 'Data URI',
                    'message': 'Link contains data: URI',
                    'details': f'href: {href[:200]}'
                })

            # 6. Suspicious query parameters
            if any(param in href.lower() for param in ['password', 'credentials', 'token=']):
                findings.append({
                    'severity': 'MEDIUM',
                    'category': 'Suspicious Parameters',
                    'message': 'URL contains sensitive-looking parameters',
                    'details': f'URL: {href[:200]}'
                })

            # Record link for the analysis table
            links_analyzed.append({
                'display_text': display_text[:100] if display_text else '(no text)',
                'href': href[:200],
                'mismatch': is_mismatch
            })

        # Check for hidden iframes
        for iframe in soup.find_all('iframe'):
            src = iframe.get('src', '')
            style = iframe.get('style', '')
            if 'display:none' in style or 'height:0' in style or 'width:0' in style:
                findings.append({
                    'severity': 'CRITICAL',
                    'category': 'Hidden Iframe in Body',
                    'message': f'Hidden iframe detected in email body',
                    'details': f'src: {src[:200]}'
                })
            elif src:
                findings.append({
                    'severity': 'HIGH',
                    'category': 'Iframe in Body',
                    'message': f'Iframe detected in email body',
                    'details': f'src: {src[:200]}'
                })

        return findings, links_analyzed

    def _extract_text_urls(self, content: str) -> List[Dict]:
        """Find and analyze all URLs in plain text content."""
        findings = []
        urls = re.findall(r'https?://[^\s<>"\']+', content)

        for url in urls:
            domain = urlparse(url).netloc.lower()

            # Raw IP address
            ip_match = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain)
            if ip_match:
                findings.append({
                    'severity': 'HIGH',
                    'category': 'IP Address URL',
                    'message': f'URL uses raw IP address instead of domain name: {domain}',
                    'details': f'URL: {url[:200]}'
                })

            # URL-encoded tricks
            decoded = unquote(url)
            if decoded != url and ('@' in decoded or '//' in decoded.split('://', 1)[-1]):
                findings.append({
                    'severity': 'HIGH',
                    'category': 'URL Encoding Trick',
                    'message': 'URL contains encoded characters that may obscure real destination',
                    'details': f'Encoded: {url[:150]}\nDecoded: {decoded[:150]}'
                })

            # Credential harvesting paths
            path = urlparse(url).path.lower()
            for cred_path in self.CREDENTIAL_PATHS:
                if cred_path in path:
                    findings.append({
                        'severity': 'MEDIUM',
                        'category': 'Credential Harvesting Pattern',
                        'message': f'URL path suggests credential harvesting: {path}',
                        'details': f'URL: {url[:200]}'
                    })
                    break

        if urls:
            findings.append({
                'severity': 'INFO',
                'category': 'URLs Found',
                'message': f'Found {len(urls)} URL(s) in email body',
                'details': ''
            })

        return findings
