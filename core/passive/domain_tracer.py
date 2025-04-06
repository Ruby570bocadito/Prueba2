import whois
import dns.resolver
from datetime import datetime
import socket
import ssl
import json
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

class DomainTracer:
    def __init__(self, domain):
        self.domain = domain
        self.results = {
            'domain': domain,
            'whois': {},
            'dns': {},
            'web': {},
            'subdomains': []
        }

    def run_whois(self):
        try:
            w = whois.whois(self.domain)
            self.results['whois'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': list(w.name_servers) if w.name_servers else []
            }
        except Exception as e:
            self.results['whois']['error'] = str(e)

    def run_dns_scan(self):
        try:
            answers = dns.resolver.resolve(self.domain, 'A')
            self.results['dns']['a_records'] = [str(r) for r in answers]
            
            answers = dns.resolver.resolve(self.domain, 'MX')
            self.results['dns']['mx_records'] = [str(r.exchange) for r in answers]
            
            answers = dns.resolver.resolve(self.domain, 'NS')
            self.results['dns']['ns_records'] = [str(r) for r in answers]
            
            answers = dns.resolver.resolve(self.domain, 'TXT')
            self.results['dns']['txt_records'] = [str(r) for r in answers]
        except Exception as e:
            self.results['dns']['error'] = str(e)

    def check_ssl(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    self.results['web']['ssl'] = {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'valid_from': cert['notBefore'],
                        'valid_to': cert['notAfter'],
                        'version': cert['version']
                    }
        except Exception as e:
            self.results['web']['ssl_error'] = str(e)

    def get_web_tech(self):
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            r = requests.get(f"https://{self.domain}", headers=headers, timeout=10)
            self.results['web']['headers'] = dict(r.headers)
            self.results['web']['status_code'] = r.status_code
            
            soup = BeautifulSoup(r.text, 'html.parser')
            meta = soup.find_all('meta')
            self.results['web']['meta'] = [str(tag) for tag in meta]
            
            scripts = soup.find_all('script', src=True)
            self.results['web']['scripts'] = [tag['src'] for tag in scripts]
        except Exception as e:
            self.results['web']['error'] = str(e)

    def find_subdomains(self, wordlist):
        for sub in wordlist:
            full_domain = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(full_domain)
                self.results['subdomains'].append(full_domain)
            except:
                continue

    def to_json(self):
        return json.dumps(self.results, indent=4)
