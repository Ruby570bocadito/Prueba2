import censys.search
import censys.certificates
import censys.ipv4
import json
import os
from datetime import datetime
from urllib.parse import urlparse

class CensysClient:
    def __init__(self, api_id=None, api_secret=None):
        self.api_id = api_id
        self.api_secret = api_secret
        self.results = {
            'hosts': [],
            'certificates': [],
            'search_results': [],
            'errors': []
        }
        
        if api_id and api_secret:
            self.certificates = censys.certificates.CensysCertificates(api_id, api_secret)
            self.ipv4 = censys.ipv4.CensysIPv4(api_id, api_secret)
            self.search = censys.search.CensysSearch(api_id, api_secret)

    def search_certificates(self, query, fields=None, max_records=100):
        """Search certificate transparency logs"""
        try:
            if not self.api_id or not self.api_secret:
                raise ValueError("Censys API credentials not configured")
            
            if not fields:
                fields = [
                    'parsed.subject_dn',
                    'parsed.issuer_dn',
                    'parsed.validity.start',
                    'parsed.validity.end',
                    'parsed.fingerprint_sha256'
                ]
                
            results = []
            for cert in self.certificates.search(query, fields, max_records=max_records):
                results.append(cert)
                self.results['certificates'].append(cert)
                
            return results
        except Exception as e:
            self.results['errors'].append(f"Certificate search error: {str(e)}")
            return []

    def search_hosts(self, query, fields=None, max_records=100):
        """Search IPv4 hosts"""
        try:
            if not self.api_id or not self.api_secret:
                raise ValueError("Censys API credentials not configured")
            
            if not fields:
                fields = [
                    'ip',
                    'protocols',
                    'location.country',
                    'ports',
                    'metadata.os'
                ]
                
            results = []
            for host in self.ipv4.search(query, fields, max_records=max_records):
                results.append(host)
                self.results['hosts'].append(host)
                
            return results
        except Exception as e:
            self.results['errors'].append(f"Host search error: {str(e)}")
            return []

    def get_certificate(self, fingerprint):
        """Get certificate details by fingerprint"""
        try:
            if not self.api_id or not self.api_secret:
                raise ValueError("Censys API credentials not configured")
            
            cert = self.certificates.view(fingerprint)
            self.results['certificates'].append(cert)
            return cert
        except Exception as e:
            self.results['errors'].append(f"Certificate lookup error: {str(e)}")
            return None

    def get_host(self, ip):
        """Get host details by IP"""
        try:
            if not self.api_id or not self.api_secret:
                raise ValueError("Censys API credentials not configured")
            
            host = self.ipv4.view(ip)
            self.results['hosts'].append(host)
            return host
        except Exception as e:
            self.results['errors'].append(f"Host lookup error: {str(e)}")
            return None

    def find_subdomains(self, domain):
        """Find subdomains via certificate transparency"""
        try:
            if not self.api_id or not self.api_secret:
                raise ValueError("Censys API credentials not configured")
            
            query = f"parsed.names: {domain}"
            fields = ['parsed.names']
            
            subdomains = set()
            for cert in self.certificates.search(query, fields):
                for name in cert.get('parsed.names', []):
                    if name.endswith(domain) and name != domain:
                        subdomains.add(name)
            
            return list(subdomains)
        except Exception as e:
            self.results['errors'].append(f"Subdomain search error: {str(e)}")
            return []

    def find_related_certs(self, domain):
        """Find certificates related to a domain"""
        try:
            if not self.api_id or not self.api_secret:
                raise ValueError("Censys API credentials not configured")
            
            query = f"parsed.subject_dn: {domain} OR parsed.names: {domain}"
            fields = [
                'parsed.subject_dn',
                'parsed.issuer_dn',
                'parsed.validity.start',
                'parsed.validity.end',
                'parsed.fingerprint_sha256'
            ]
            
            results = []
            for cert in self.certificates.search(query, fields):
                results.append(cert)
                self.results['certificates'].append(cert)
                
            return results
        except Exception as e:
            self.results['errors'].append(f"Related certs error: {str(e)}")
            return []

    def to_json(self):
        """Return results as JSON"""
        return json.dumps(self.results, indent=4)

    def save_report(self, output_dir='output'):
        """Save scan results to file"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = f"{output_dir}/censys_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            f.write(self.to_json())

        return filename
