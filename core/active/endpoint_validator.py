import requests
import json
import os
from datetime import datetime
from urllib.parse import urlparse
import socket
import ssl
import re

class EndpointValidator:
    def __init__(self):
        self.results = {
            'endpoints': [],
            'errors': []
        }
        self.headers = {
            'User-Agent': 'TargetTrace/1.0',
            'Accept': '*/*'
        }

    def validate_endpoint(self, url):
        """Validate and test a single endpoint"""
        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                url = f"http://{url}"
                parsed = urlparse(url)

            endpoint_result = {
                'url': url,
                'dns': {},
                'ssl': {},
                'http': {},
                'security_headers': {},
                'vulnerabilities': []
            }

            # DNS validation
            self._check_dns(parsed.hostname, endpoint_result)

            # SSL/TLS validation (for HTTPS)
            if parsed.scheme == 'https':
                self._check_ssl(parsed.hostname, endpoint_result)

            # HTTP validation
            self._check_http(url, endpoint_result)

            # Security headers check
            self._check_security_headers(url, endpoint_result)

            # Common vulnerability checks
            self._check_vulnerabilities(url, endpoint_result)

            self.results['endpoints'].append(endpoint_result)

        except Exception as e:
            self.results['errors'].append(f"Error validating {url}: {str(e)}")

    def _check_dns(self, hostname, result):
        """Check DNS records for hostname"""
        try:
            # A records
            result['dns']['a_records'] = socket.gethostbyname_ex(hostname)[2]
            
            # MX records (if domain)
            if '.' in hostname and not any(char.isdigit() for char in hostname.split('.')[0]):
                try:
                    result['dns']['mx_records'] = [r[1] for r in socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)]
                except:
                    pass
        except Exception as e:
            result['dns']['error'] = str(e)

    def _check_ssl(self, hostname, result):
        """Check SSL/TLS configuration"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result['ssl']['issuer'] = dict(x[0] for x in cert['issuer'])
                    result['ssl']['valid_from'] = cert['notBefore']
                    result['ssl']['valid_to'] = cert['notAfter']
                    result['ssl']['version'] = cert['version']
                    result['ssl']['cipher'] = ssock.cipher()
        except Exception as e:
            result['ssl']['error'] = str(e)

    def _check_http(self, url, result):
        """Check HTTP response and headers"""
        try:
            r = requests.get(url, headers=self.headers, timeout=10, allow_redirects=False)
            result['http']['status'] = r.status_code
            result['http']['headers'] = dict(r.headers)
            result['http']['server'] = r.headers.get('Server', '')
            result['http']['content_type'] = r.headers.get('Content-Type', '')
            
            # Check for redirects
            if 300 <= r.status_code < 400:
                result['http']['redirect'] = r.headers.get('Location', '')
        except Exception as e:
            result['http']['error'] = str(e)

    def _check_security_headers(self, url, result):
        """Check for important security headers"""
        try:
            r = requests.get(url, headers=self.headers, timeout=5)
            headers = r.headers
            
            security_headers = {
                'strict-transport-security': headers.get('Strict-Transport-Security', 'missing'),
                'content-security-policy': headers.get('Content-Security-Policy', 'missing'),
                'x-frame-options': headers.get('X-Frame-Options', 'missing'),
                'x-content-type-options': headers.get('X-Content-Type-Options', 'missing'),
                'x-xss-protection': headers.get('X-XSS-Protection', 'missing'),
                'referrer-policy': headers.get('Referrer-Policy', 'missing')
            }
            
            result['security_headers'] = security_headers
        except:
            pass

    def _check_vulnerabilities(self, url, result):
        """Check for common vulnerabilities"""
        try:
            # Check for directory traversal
            test_url = f"{url}/../../../../etc/passwd"
            r = requests.get(test_url, headers=self.headers, timeout=5)
            if "root:" in r.text:
                result['vulnerabilities'].append('directory_traversal')

            # Check for basic SQLi
            test_url = f"{url}?id=1'"
            r = requests.get(test_url, headers=self.headers, timeout=5)
            if "SQL syntax" in r.text or "mysql" in r.text.lower():
                result['vulnerabilities'].append('possible_sqli')

            # Check for XSS
            test_url = f"{url}?q=<script>alert(1)</script>"
            r = requests.get(test_url, headers=self.headers, timeout=5)
            if "<script>alert(1)</script>" in r.text:
                result['vulnerabilities'].append('possible_xss')
        except:
            pass

    def validate_multiple(self, urls):
        """Validate multiple endpoints"""
        for url in urls:
            self.validate_endpoint(url)

    def to_json(self):
        """Return results as JSON"""
        return json.dumps(self.results, indent=4)

    def save_report(self, output_dir='output'):
        """Save validation results to file"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = f"{output_dir}/endpoint_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            f.write(self.to_json())

        return filename
