#!/usr/bin/env python3
"""
Email Header Analyzer
Analyzes email headers for signs of spoofing, forgery, and suspicious routing.
"""

import email
from email import policy
from email.parser import BytesParser
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class HeaderAnalyzer:
    """Analyzes email headers for security indicators and anomalies."""

    def analyze(self, email_folder: Path, mode: str = 'normal', eml_msg=None) -> Dict:
        """
        Analyze email headers from a headers.txt file or parsed EML message.

        Args:
            email_folder: Path to the email folder containing attached_files/headers.txt.
            mode: 'normal' to read headers.txt, 'eml' to use provided eml_msg.
            eml_msg: Pre-parsed email message object (used when mode='eml').

        Returns:
            Dict with tool_name, timestamp, findings, tools_used, and header_data.
        """
        result = {
            'tool_name': 'Email Header Analyzer',
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'tools_used': [],
            'header_data': {}
        }

        msg = None

        if mode == 'eml' and eml_msg is not None:
            msg = eml_msg
            result['tools_used'].append({
                'tool': 'email.parser (EML mode)',
                'status': 'success'
            })
        else:
            # Normal mode: read headers.txt from attached_files
            headers_path = Path(email_folder) / 'attached_files' / 'headers.txt'
            if headers_path.exists():
                try:
                    raw_headers = headers_path.read_text(encoding='utf-8', errors='replace')
                    msg = email.message_from_string(raw_headers)
                    result['tools_used'].append({
                        'tool': 'email.message_from_string',
                        'status': 'success',
                        'source': str(headers_path)
                    })
                except Exception as e:
                    result['findings'].append({
                        'severity': 'MEDIUM',
                        'category': 'Parse Error',
                        'message': f'Failed to parse headers.txt: {e}',
                        'details': str(headers_path)
                    })
                    result['tools_used'].append({
                        'tool': 'email.message_from_string',
                        'status': 'error',
                        'error': str(e)
                    })
                    return result

        if msg is None:
            result['findings'].append({
                'severity': 'INFO',
                'category': 'No Headers',
                'message': 'No email headers available for analysis',
                'details': 'Neither headers.txt nor EML message was provided'
            })
            return result

        # Extract header summary
        result['header_data'] = self._extract_header_summary(msg)

        # Run all sub-checks and merge findings
        result['findings'].extend(self._analyze_received_chain(msg))
        result['findings'].extend(self._check_auth_results(msg))
        result['findings'].extend(self._check_sender_mismatch(msg))
        result['findings'].extend(self._analyze_xmailer(msg))
        result['findings'].extend(self._hop_analysis(msg))

        return result

    def _extract_header_summary(self, msg) -> Dict:
        """
        Extract a summary of key header fields.

        Returns:
            Dict with from, to, subject, date, reply_to, return_path,
            message_id, x_mailer, and received_count.
        """
        return {
            'from': msg.get('From', ''),
            'to': msg.get('To', ''),
            'subject': msg.get('Subject', ''),
            'date': msg.get('Date', ''),
            'reply_to': msg.get('Reply-To', ''),
            'return_path': msg.get('Return-Path', ''),
            'message_id': msg.get('Message-ID', ''),
            'x_mailer': msg.get('X-Mailer', '') or msg.get('User-Agent', ''),
            'received_count': len(msg.get_all('Received', []))
        }

    def _analyze_received_chain(self, msg) -> List[Dict]:
        """
        Parse all Received headers to trace the email routing chain.

        Extracts IP addresses and from/by hostnames from each hop.
        The bottom-most Received header is identified as the originating server.
        No Received headers at all indicates possible forgery.

        Returns:
            List of finding dicts.
        """
        findings = []
        received_headers = msg.get_all('Received', [])

        if not received_headers:
            findings.append({
                'severity': 'HIGH',
                'category': 'Missing Received Headers',
                'message': 'No Received headers found - possible email forgery',
                'details': 'Legitimate emails should have at least one Received header '
                           'showing the mail transfer path'
            })
            return findings

        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        from_pattern = re.compile(r'from\s+([\w.\-]+)', re.IGNORECASE)
        by_pattern = re.compile(r'by\s+([\w.\-]+)', re.IGNORECASE)

        chain = []
        for i, header in enumerate(received_headers):
            ips = ip_pattern.findall(header)
            from_match = from_pattern.search(header)
            by_match = by_pattern.search(header)

            hop_info = {
                'hop': i + 1,
                'ips': ips,
                'from_host': from_match.group(1) if from_match else None,
                'by_host': by_match.group(1) if by_match else None,
                'raw': header.strip()[:200]
            }
            chain.append(hop_info)

        # Bottom Received header = originating server (last in list, first added)
        origin = chain[-1] if chain else None
        if origin:
            origin_ip = origin['ips'][0] if origin['ips'] else 'unknown'
            origin_host = origin['from_host'] or 'unknown'
            findings.append({
                'severity': 'INFO',
                'category': 'Origin Server',
                'message': f'Email originated from {origin_host} (IP: {origin_ip})',
                'details': f'Originating Received header (hop {origin["hop"]}): '
                           f'{origin["raw"]}'
            })

        return findings

    def _check_auth_results(self, msg) -> List[Dict]:
        """
        Parse the Authentication-Results header for SPF, DKIM, and DMARC results.

        Severity mapping:
            SPF:  fail=HIGH, softfail=MEDIUM, pass=INFO
            DKIM: fail=HIGH, pass=INFO
            DMARC: fail=CRITICAL, pass=INFO
            No Authentication-Results header = MEDIUM

        Returns:
            List of finding dicts.
        """
        findings = []
        auth_results = msg.get('Authentication-Results', '')

        if not auth_results:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Missing Authentication-Results',
                'message': 'No Authentication-Results header found',
                'details': 'Cannot verify SPF, DKIM, or DMARC status. '
                           'This header is typically added by the receiving mail server.'
            })
            return findings

        auth_lower = auth_results.lower()

        # SPF check
        spf_match = re.search(r'spf\s*=\s*(\w+)', auth_lower)
        if spf_match:
            spf_result = spf_match.group(1)
            if spf_result == 'fail':
                findings.append({
                    'severity': 'HIGH',
                    'category': 'SPF Failure',
                    'message': 'SPF check failed - sender IP not authorized',
                    'details': f'SPF result: {spf_result}. The sending server is not '
                               f'authorized to send on behalf of the sender domain.'
                })
            elif spf_result == 'softfail':
                findings.append({
                    'severity': 'MEDIUM',
                    'category': 'SPF Softfail',
                    'message': 'SPF check returned softfail',
                    'details': f'SPF result: {spf_result}. The sending server is not '
                               f'explicitly authorized but not explicitly denied.'
                })
            elif spf_result == 'pass':
                findings.append({
                    'severity': 'INFO',
                    'category': 'SPF Pass',
                    'message': 'SPF check passed',
                    'details': 'The sending server is authorized to send on behalf '
                               'of the sender domain.'
                })

        # DKIM check
        dkim_match = re.search(r'dkim\s*=\s*(\w+)', auth_lower)
        if dkim_match:
            dkim_result = dkim_match.group(1)
            if dkim_result == 'fail':
                findings.append({
                    'severity': 'HIGH',
                    'category': 'DKIM Failure',
                    'message': 'DKIM signature verification failed',
                    'details': f'DKIM result: {dkim_result}. The email signature is '
                               f'invalid - the message may have been tampered with.'
                })
            elif dkim_result == 'pass':
                findings.append({
                    'severity': 'INFO',
                    'category': 'DKIM Pass',
                    'message': 'DKIM signature verified successfully',
                    'details': 'The email signature is valid and the message has not '
                               'been modified in transit.'
                })

        # DMARC check
        dmarc_match = re.search(r'dmarc\s*=\s*(\w+)', auth_lower)
        if dmarc_match:
            dmarc_result = dmarc_match.group(1)
            if dmarc_result == 'fail':
                findings.append({
                    'severity': 'CRITICAL',
                    'category': 'DMARC Failure',
                    'message': 'DMARC check failed - high likelihood of spoofing',
                    'details': f'DMARC result: {dmarc_result}. The email fails domain-based '
                               f'authentication. This is a strong indicator of spoofing.'
                })
            elif dmarc_result == 'pass':
                findings.append({
                    'severity': 'INFO',
                    'category': 'DMARC Pass',
                    'message': 'DMARC check passed',
                    'details': 'The email passes domain-based message authentication.'
                })

        return findings

    def _check_sender_mismatch(self, msg) -> List[Dict]:
        """
        Compare domains in From, Reply-To, and Return-Path headers.

        Domain mismatches indicate potential phishing:
            Reply-To domain != From domain = HIGH
            Return-Path domain != From domain = MEDIUM

        Returns:
            List of finding dicts.
        """
        findings = []
        email_regex = re.compile(r'[\w.+-]+@([\w.-]+\.\w+)')

        from_header = msg.get('From', '')
        reply_to_header = msg.get('Reply-To', '')
        return_path_header = msg.get('Return-Path', '')

        # Extract domains
        from_match = email_regex.search(from_header)
        reply_to_match = email_regex.search(reply_to_header)
        return_path_match = email_regex.search(return_path_header)

        from_domain = from_match.group(1).lower() if from_match else None

        if not from_domain:
            return findings

        # Check Reply-To mismatch
        if reply_to_match:
            reply_to_domain = reply_to_match.group(1).lower()
            if reply_to_domain != from_domain:
                findings.append({
                    'severity': 'HIGH',
                    'category': 'Reply-To Mismatch',
                    'message': f'Reply-To domain ({reply_to_domain}) differs from '
                               f'From domain ({from_domain})',
                    'details': f'From: {from_header} | Reply-To: {reply_to_header}. '
                               f'Replies will go to a different domain than the apparent sender.'
                })

        # Check Return-Path mismatch
        if return_path_match:
            return_path_domain = return_path_match.group(1).lower()
            if return_path_domain != from_domain:
                findings.append({
                    'severity': 'MEDIUM',
                    'category': 'Return-Path Mismatch',
                    'message': f'Return-Path domain ({return_path_domain}) differs from '
                               f'From domain ({from_domain})',
                    'details': f'From: {from_header} | Return-Path: {return_path_header}. '
                               f'Bounce messages will go to a different domain.'
                })

        return findings

    def _analyze_xmailer(self, msg) -> List[Dict]:
        """
        Check X-Mailer and User-Agent headers for suspicious mail clients.

        Suspicious mailers: PHPMailer, Microsoft CDO, The Bat!, ZuckMail.

        Returns:
            List of finding dicts.
        """
        findings = []
        x_mailer = msg.get('X-Mailer', '') or msg.get('User-Agent', '')

        if not x_mailer:
            return findings

        suspicious_mailers = ['PHPMailer', 'Microsoft CDO', 'The Bat!', 'ZuckMail']

        for mailer in suspicious_mailers:
            if mailer.lower() in x_mailer.lower():
                findings.append({
                    'severity': 'MEDIUM',
                    'category': 'Suspicious Mailer',
                    'message': f'Suspicious mail client detected: {mailer}',
                    'details': f'X-Mailer/User-Agent: {x_mailer}. This mail client '
                               f'is commonly associated with spam or phishing campaigns.'
                })
                break  # Report only the first match

        return findings

    def _hop_analysis(self, msg) -> List[Dict]:
        """
        Count the number of Received headers (hops) in the email routing chain.

        More than 10 hops may indicate suspicious routing or relay abuse.

        Returns:
            List of finding dicts.
        """
        findings = []
        received_headers = msg.get_all('Received', [])
        hop_count = len(received_headers)

        if hop_count > 10:
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Excessive Hops',
                'message': f'Email passed through {hop_count} mail servers',
                'details': f'The email has {hop_count} Received headers, which exceeds '
                           f'the typical threshold of 10. This may indicate relay abuse, '
                           f'open relay exploitation, or deliberate routing obfuscation.'
            })

        return findings
