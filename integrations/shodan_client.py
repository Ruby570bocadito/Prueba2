import shodan
import json
import os
from datetime import datetime
from urllib.parse import urlparse

class ShodanClient:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.api = shodan.Shodan(api_key) if api_key else None
        self.results = {
            'hosts': [],
            'search_results': [],
            'errors': []
        }

    def host_info(self, ip):
        """Get information about a specific host"""
        try:
            if not self.api_key:
                raise ValueError("Shodan API key not configured")
            
            host = self.api.host(ip)
            self.results['hosts'].append(host)
            return host
        except shodan.APIError as e:
            self.results['errors'].append(f"Shodan API error: {str(e)}")
            return None
        except Exception as e:
            self.results['errors'].append(f"Host lookup error: {str(e)}")
            return None

    def search(self, query, limit=100):
        """Search Shodan for devices matching query"""
        try:
            if not self.api_key:
                raise ValueError("Shodan API key not configured")
            
            results = self.api.search(query, limit=limit)
            self.results['search_results'].extend(results['matches'])
            return results['matches']
        except shodan.APIError as e:
            self.results['errors'].append(f"Shodan API error: {str(e)}")
            return []
        except Exception as e:
            self.results['errors'].append(f"Search error: {str(e)}")
            return []

    def scan_ports(self, ip, ports=None):
        """Scan common ports on an IP"""
        try:
            if not self.api_key:
                raise ValueError("Shodan API key not configured")
            
            if not ports:
                ports = "21,22,80,443,3306,3389,8080"
            
            results = self.api.scan(ip, ports=ports)
            return results
        except shodan.APIError as e:
            self.results['errors'].append(f"Shodan API error: {str(e)}")
            return None
        except Exception as e:
            self.results['errors'].append(f"Port scan error: {str(e)}")
            return None

    def find_services(self, service, country=None, limit=100):
        """Find instances of a specific service"""
        try:
            if not self.api_key:
                raise ValueError("Shodan API key not configured")
            
            query = f"product:{service}"
            if country:
                query += f" country:{country}"
            
            results = self.api.search(query, limit=limit)
            self.results['search_results'].extend(results['matches'])
            return results['matches']
        except shodan.APIError as e:
            self.results['errors'].append(f"Shodan API error: {str(e)}")
            return []
        except Exception as e:
            self.results['errors'].append(f"Service search error: {str(e)}")
            return []

    def find_vulnerable_devices(self, vuln, limit=100):
        """Find devices vulnerable to a specific CVE"""
        try:
            if not self.api_key:
                raise ValueError("Shodan API key not configured")
            
            results = self.api.search(f"vuln:{vuln}", limit=limit)
            self.results['search_results'].extend(results['matches'])
            return results['matches']
        except shodan.APIError as e:
            self.results['errors'].append(f"Shodan API error: {str(e)}")
            return []
        except Exception as e:
            self.results['errors'].append(f"Vulnerability search error: {str(e)}")
            return []

    def domain_info(self, domain):
        """Get information about a domain from Shodan"""
        try:
            if not self.api_key:
                raise ValueError("Shodan API key not configured")
            
            # First resolve domain to IP
            ip = socket.gethostbyname(domain)
            
            # Then get host info
            host = self.api.host(ip)
            host['domain'] = domain
            self.results['hosts'].append(host)
            return host
        except shodan.APIError as e:
            self.results['errors'].append(f"Shodan API error: {str(e)}")
            return None
        except Exception as e:
            self.results['errors'].append(f"Domain lookup error: {str(e)}")
            return None

    def to_json(self):
        """Return results as JSON"""
        return json.dumps(self.results, indent=4)

    def save_report(self, output_dir='output'):
        """Save scan results to file"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = f"{output_dir}/shodan_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            f.write(self.to_json())

        return filename
