import requests
import re
import json
from datetime import datetime
import os
import hashlib
from urllib.parse import urlparse
import dns.resolver

class LeakDetective:
    def __init__(self, domain):
        self.domain = domain
        self.results = {
            'domain': domain,
            'github_leaks': [],
            'pastebin_leaks': [],
            's3_buckets': [],
            'database_exposures': [],
            'api_keys': []
        }

    def search_github(self, keywords=None):
        """Search GitHub for potential leaks (simplified)"""
        if not keywords:
            keywords = [self.domain, f"@{self.domain}"]

        # In a real implementation, this would use GitHub API
        common_leaks = [
            {
                'repository': 'example/leaked-code',
                'file': 'config.json',
                'content': f"DB_PASSWORD=password123\nAPI_KEY=abc123xyz\nSMTP_USER=admin@{self.domain}",
                'url': f'https://github.com/example/leaked-code/blob/main/config.json'
            },
            {
                'repository': 'test/old-project',
                'file': '.env',
                'content': f"AWS_ACCESS_KEY=AKIAEXAMPLE\nAWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                'url': f'https://github.com/test/old-project/blob/main/.env'
            }
        ]
        
        for leak in common_leaks:
            for keyword in keywords:
                if keyword.lower() in leak['content'].lower():
                    self.results['github_leaks'].append(leak)
                    break

    def check_pastebin(self):
        """Check Pastebin for leaks (simplified)"""
        # In a real implementation, this would use Pastebin API or scraping
        common_pastes = [
            {
                'id': 'a1b2c3d4',
                'content': f"Database connection string for {self.domain}: mongodb://admin:password@db.{self.domain}:27017",
                'url': 'https://pastebin.com/a1b2c3d4'
            },
            {
                'id': 'x9y8z7w6',
                'content': f"Email credentials for {self.domain}: user=admin@domain.com password=Winter2023!",
                'url': 'https://pastebin.com/x9y8z7w6'
            }
        ]

        for paste in common_pastes:
            if self.domain.lower() in paste['content'].lower():
                self.results['pastebin_leaks'].append(paste)

    def find_s3_buckets(self):
        """Find potentially open S3 buckets"""
        common_buckets = [
            f"{self.domain}-assets",
            f"{self.domain}-backups",
            f"{self.domain}-storage",
            f"dev-{self.domain}",
            f"prod-{self.domain}"
        ]

        for bucket in common_buckets:
            try:
                url = f"http://{bucket}.s3.amazonaws.com"
                r = requests.head(url, timeout=5)
                if r.status_code == 200:
                    self.results['s3_buckets'].append({
                        'bucket': bucket,
                        'url': url,
                        'status': 'public'
                    })
                elif r.status_code == 403:
                    self.results['s3_buckets'].append({
                        'bucket': bucket,
                        'url': url,
                        'status': 'exists_but_private'
                    })
            except:
                continue

    def extract_sensitive_data(self, text):
        """Extract potential API keys and credentials from text"""
        # AWS keys
        aws_keys = re.findall(r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])', text)
        self.results['api_keys'].extend([{'type': 'aws_access_key', 'value': k} for k in aws_keys])

        # Generic API keys
        api_keys = re.findall(r'(?i)(api|key|token|secret)[_-]?key[=:]\s*([a-z0-9]{32,})', text)
        self.results['api_keys'].extend([{'type': 'generic_api_key', 'value': k[1]} for k in api_keys])

    def to_json(self):
        return json.dumps(self.results, indent=4)

    def save_report(self, output_dir='output'):
        """Save leak report to file"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = f"{output_dir}/{self.domain}_leaks.json"
        with open(filename, 'w') as f:
            f.write(self.to_json())

        return filename
