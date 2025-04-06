import requests
import json
import os
from datetime import datetime
from urllib.parse import urlparse

class OTXClient:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json"
        } if api_key else {}
        self.results = {
            'pulses': [],
            'indicators': [],
            'malware': [],
            'errors': []
        }

    def get_pulse_details(self, pulse_id):
        """Get details about a specific threat pulse"""
        try:
            if not self.api_key:
                raise ValueError("OTX API key not configured")
            
            response = requests.get(
                f"{self.base_url}/pulses/{pulse_id}",
                headers=self.headers
            )
            response.raise_for_status()
            
            pulse = response.json()
            self.results['pulses'].append(pulse)
            return pulse
        except Exception as e:
            self.results['errors'].append(f"Pulse details error: {str(e)}")
            return None

    def get_indicator_details(self, indicator_type, indicator):
        """Get details about a specific indicator"""
        try:
            if not self.api_key:
                raise ValueError("OTX API key not configured")
            
            response = requests.get(
                f"{self.base_url}/indicators/{indicator_type}/{indicator}/general",
                headers=self.headers
            )
            response.raise_for_status()
            
            details = response.json()
            self.results['indicators'].append(details)
            return details
        except Exception as e:
            self.results['errors'].append(f"Indicator details error: {str(e)}")
            return None

    def search_pulses(self, query, limit=10):
        """Search for threat pulses"""
        try:
            if not self.api_key:
                raise ValueError("OTX API key not configured")
            
            params = {
                'q': query,
                'limit': limit
            }
            
            response = requests.get(
                f"{self.base_url}/search/pulses",
                headers=self.headers,
                params=params
            )
            response.raise_for_status()
            
            results = response.json()
            self.results['pulses'].extend(results.get('results', []))
            return results.get('results', [])
        except Exception as e:
            self.results['errors'].append(f"Pulse search error: {str(e)}")
            return []

    def get_domain_indicators(self, domain):
        """Get threat indicators for a domain"""
        try:
            if not self.api_key:
                raise ValueError("OTX API key not configured")
            
            response = requests.get(
                f"{self.base_url}/indicators/domain/{domain}",
                headers=self.headers
            )
            response.raise_for_status()
            
            indicators = response.json()
            self.results['indicators'].extend(indicators.get('results', []))
            return indicators.get('results', [])
        except Exception as e:
            self.results['errors'].append(f"Domain indicators error: {str(e)}")
            return []

    def get_ip_indicators(self, ip):
        """Get threat indicators for an IP address"""
        try:
            if not self.api_key:
                raise ValueError("OTX API key not configured")
            
            response = requests.get(
                f"{self.base_url}/indicators/IPv4/{ip}",
                headers=self.headers
            )
            response.raise_for_status()
            
            indicators = response.json()
            self.results['indicators'].extend(indicators.get('results', []))
            return indicators.get('results', [])
        except Exception as e:
            self.results['errors'].append(f"IP indicators error: {str(e)}")
            return []

    def get_malware_samples(self, hash_value):
        """Get malware samples by hash"""
        try:
            if not self.api_key:
                raise ValueError("OTX API key not configured")
            
            response = requests.get(
                f"{self.base_url}/indicators/file/{hash_value}/analysis",
                headers=self.headers
            )
            response.raise_for_status()
            
            analysis = response.json()
            self.results['malware'].append(analysis)
            return analysis
        except Exception as e:
            self.results['errors'].append(f"Malware analysis error: {str(e)}")
            return None

    def get_user_pulses(self, username):
        """Get pulses created by a specific user"""
        try:
            if not self.api_key:
                raise ValueError("OTX API key not configured")
            
            response = requests.get(
                f"{self.base_url}/users/{username}/pulses",
                headers=self.headers
            )
            response.raise_for_status()
            
            pulses = response.json()
            self.results['pulses'].extend(pulses.get('results', []))
            return pulses.get('results', [])
        except Exception as e:
            self.results['errors'].append(f"User pulses error: {str(e)}")
            return []

    def to_json(self):
        """Return results as JSON"""
        return json.dumps(self.results, indent=4)

    def save_report(self, output_dir='output'):
        """Save scan results to file"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = f"{output_dir}/otx_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            f.write(self.to_json())

        return filename
