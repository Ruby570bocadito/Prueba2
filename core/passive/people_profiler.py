import requests
from bs4 import BeautifulSoup
import re
import json
from urllib.parse import urljoin
from datetime import datetime
import os

class PeopleProfiler:
    def __init__(self, name, domain=None):
        self.name = name
        self.domain = domain
        self.results = {
            'name': name,
            'social_media': {},
            'professional_profiles': {},
            'email_addresses': [],
            'phone_numbers': [],
            'possible_credentials': []
        }

    def search_social_media(self):
        """Search for social media profiles"""
        platforms = {
            'twitter': f'https://twitter.com/{self.name}',
            'linkedin': f'https://www.linkedin.com/in/{self.name}',
            'github': f'https://github.com/{self.name}'
        }

        for platform, url in platforms.items():
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200:
                    self.results['social_media'][platform] = {
                        'url': url,
                        'exists': True
                    }
            except:
                self.results['social_media'][platform] = {
                    'url': url,
                    'exists': False
                }

    def search_professional_sites(self):
        """Search professional networking sites"""
        if not self.domain:
            return

        urls = [
            f'https://{self.domain}/team',
            f'https://{self.domain}/about',
            f'https://{self.domain}/people'
        ]

        for url in urls:
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, 'html.parser')
                    if self.name.lower() in soup.get_text().lower():
                        self.results['professional_profiles'][url] = {
                            'found': True,
                            'mentions': soup.get_text().lower().count(self.name.lower())
                        }
            except:
                continue

    def extract_contact_info(self, text):
        """Extract emails and phone numbers from text"""
        # Email regex
        emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
        self.results['email_addresses'].extend(list(set(emails)))

        # Phone regex (basic)
        phones = re.findall(r'(\d{3}[-\.\s]??\d{3}[-\.\s]??\d{4}|\(\d{3}\)\s*\d{3}[-\.\s]??\d{4}|\d{3}[-\.\s]??\d{4})', text)
        self.results['phone_numbers'].extend(list(set(phones)))

    def check_breaches(self):
        """Check for known credential breaches (simplified)"""
        # In a real implementation, this would use HaveIBeenPwned API or similar
        common_breaches = [
            {'service': 'linkedin_2012', 'count': '165M'},
            {'service': 'adobe_2013', 'count': '153M'},
            {'service': 'dropbox_2012', 'count': '68M'}
        ]
        self.results['possible_credentials'] = common_breaches

    def to_json(self):
        return json.dumps(self.results, indent=4)

    def save_report(self, output_dir='output'):
        """Save profile report to file"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = f"{output_dir}/{self.name.replace(' ', '_')}_profile.json"
        with open(filename, 'w') as f:
            f.write(self.to_json())

        return filename
