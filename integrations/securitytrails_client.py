import requests
import json
import os
from datetime import datetime
from urllib.parse import urlparse

class SecurityTrailsClient:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://api.securitytrails.com/v1"
        self.headers = {
            "Accept": "application/json",
            "APIKEY": api_key
        } if api_key else {}
        self.results = {
            'domain_info': [],
            'dns_records': [],
            'whois': [],
            'errors': []
        }

    def get_domain_info(self, domain):
        """Get general domain information"""
        try:
            if not self.api_key:
                raise ValueError("SecurityTrails API key not configured")
            
            response = requests.get(
                f"{self.base_url}/domain/{domain}",
                headers=self.headers
            )
            response.raise_for_status()
            
            info = response.json()
            self.results['domain_info'].append(info)
            return info
        except Exception as e:
            self.results['errors'].append(f"Domain info error: {str(e)}")
            return None

    def get_dns_history(self, domain, record_type='a'):
        """Get historical DNS records for a domain"""
        try:
            if not self.api_key:
                raise ValueError("SecurityTrails API key not configured")
            
            response = requests.get(
                f"{self.base_url}/history/{domain}/dns/{record_type}",
                headers=self.headers
            )
            response.raise_for_status()
            
            history = response.json()
            self.results['dns_records'].extend(history.get('records', []))
            return history.get('records', [])
        except Exception as e:
            self.results['errors'].append(f"DNS history error: {str(e)}")
            return []

    def get_current_dns(self, domain, record_type='a'):
        """Get current DNS records for a domain"""
        try:
            if not self.api_key:
                raise ValueError("SecurityTrails API key not configured")
            
            response = requests.get(
                f"{self.base_url}/domain/{domain}/dns/{record_type}",
                headers=self.headers
            )
            response.raise_for_status()
            
            records = response.json()
            self.results['dns_records'].extend(records.get('records', []))
            return records.get('records', [])
        except Exception as e:
            self.results['errors'].append(f"Current DNS error: {str(e)}")
            return []

    def get_whois(self, domain):
        """Get WHOIS information for a domain"""
        try:
            if not self.api_key:
                raise ValueError("SecurityTrails API key not configured")
            
            response = requests.get(
                f"{self.base_url}/domain/{domain}/whois",
                headers=self.headers
            )
            response.raise_for_status()
            
            whois = response.json()
            self.results['whois'].append(whois)
            return whois
        except Exception as e:
            self.results['errors'].append(f"WHOIS error: {str(e)}")
            return None

    def get_subdomains(self, domain):
        """Get subdomains for a domain"""
        try:
            if not self.api_key:
                raise ValueError("SecurityTrails API key not configured")
            
            response = requests.get(
                f"{self.base_url}/domain/{domain}/subdomains",
                headers=self.headers
            )
            response.raise_for_status()
            
            subdomains = response.json()
            return subdomains.get('subdomains', [])
        except Exception as e:
            self.results['errors'].append(f"Subdomains error: {str(e)}")
            return []

    def get_associated_domains(self, domain):
        """Get domains associated with the same owner"""
        try:
            if not self.api_key:
                raise ValueError("SecurityTrails API key not configured")
            
            response = requests.get(
                f"{self.base_url}/domain/{domain}/associated",
                headers=self.headers
            )
            response.raise_for_status()
            
            domains = response.json()
            return domains.get('records', [])
        except Exception as e:
            self.results['errors'].append(f"Associated domains error: {str(e)}")
            return []

    def search_domains(self, query, filter_type='dns'):
        """Search domains using SecurityTrails DSL"""
        try:
            if not self.api_key:
                raise ValueError("SecurityTrails API key not configured")
            
            params = {
                'query': query,
                'filter': filter_type
            }
            
            response = requests.get(
                f"{self.base_url}/domains/list",
                headers=self.headers,
                params=params
            )
            response.raise_for_status()
            
            results = response.json()
            return results.get('records', [])
        except Exception as e:
            self.results['errors'].append(f"Domain search error: {str(e)}")
            return []

    def to_json(self):
        """Return results as JSON"""
        return json.dumps(self.results, indent=4)

    def save_report(self, output_dir='output'):
        """Save scan results to file"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = f"{output_dir}/securitytrails_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            f.write(self.to_json())

        return filename
