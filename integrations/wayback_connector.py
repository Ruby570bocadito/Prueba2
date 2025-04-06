import requests
import json
import os
from datetime import datetime
from urllib.parse import urlparse

class WaybackConnector:
    def __init__(self):
        self.base_url = "https://web.archive.org"
        self.cdx_url = "https://web.archive.org/cdx/search/cdx"
        self.results = {
            'snapshots': [],
            'pages': [],
            'errors': []
        }

    def get_snapshots(self, url, limit=100):
        """Get historical snapshots for a URL"""
        try:
            params = {
                'url': url,
                'output': 'json',
                'limit': limit,
                'collapse': 'timestamp:6'  # Group by hour
            }
            
            response = requests.get(self.cdx_url, params=params)
            response.raise_for_status()
            
            snapshots = response.json()
            if len(snapshots) > 1:  # First row is headers
                for snapshot in snapshots[1:]:
                    self.results['snapshots'].append({
                        'url': snapshot[0],
                        'timestamp': snapshot[1],
                        'status': snapshot[2],
                        'digest': snapshot[3],
                        'length': snapshot[4]
                    })
                return self.results['snapshots']
            return []
        except Exception as e:
            self.results['errors'].append(f"Snapshot fetch error: {str(e)}")
            return []

    def get_page(self, url, timestamp=None):
        """Get archived page content"""
        try:
            if not timestamp:
                # Get most recent snapshot
                snapshots = self.get_snapshots(url, limit=1)
                if not snapshots:
                    return None
                timestamp = snapshots[0]['timestamp']
            
            wayback_url = f"{self.base_url}/web/{timestamp}id_/{url}"
            response = requests.get(wayback_url)
            response.raise_for_status()
            
            page_data = {
                'url': url,
                'timestamp': timestamp,
                'content': response.text,
                'wayback_url': wayback_url
            }
            
            self.results['pages'].append(page_data)
            return page_data
        except Exception as e:
            self.results['errors'].append(f"Page fetch error: {str(e)}")
            return None

    def search_domain(self, domain, limit=100):
        """Search for all pages under a domain"""
        try:
            params = {
                'url': f"*.{domain}/*",
                'output': 'json',
                'limit': limit,
                'collapse': 'urlkey'  # Group by URL
            }
            
            response = requests.get(self.cdx_url, params=params)
            response.raise_for_status()
            
            pages = response.json()
            if len(pages) > 1:  # First row is headers
                for page in pages[1:]:
                    self.results['pages'].append({
                        'url': page[0],
                        'timestamp': page[1],
                        'status': page[2],
                        'digest': page[3],
                        'length': page[4]
                    })
                return self.results['pages']
            return []
        except Exception as e:
            self.results['errors'].append(f"Domain search error: {str(e)}")
            return []

    def find_changes(self, url, timestamp1, timestamp2):
        """Compare two versions of a page"""
        try:
            page1 = self.get_page(url, timestamp1)
            page2 = self.get_page(url, timestamp2)
            
            if not page1 or not page2:
                return None
                
            # Simple comparison (in real implementation would use diff library)
            changes = {
                'url': url,
                'timestamp1': timestamp1,
                'timestamp2': timestamp2,
                'length_diff': len(page2['content']) - len(page1['content']),
                'content_diff': None  # Would be actual diff in real implementation
            }
            
            return changes
        except Exception as e:
            self.results['errors'].append(f"Change detection error: {str(e)}")
            return None

    def find_historical_records(self, domain, year=None):
        """Find historical records for a domain"""
        try:
            params = {
                'url': domain,
                'output': 'json'
            }
            if year:
                params['from'] = f"{year}0101"
                params['to'] = f"{year}1231"
                
            response = requests.get(self.cdx_url, params=params)
            response.raise_for_status()
            
            records = response.json()
            if len(records) > 1:  # First row is headers
                for record in records[1:]:
                    self.results['snapshots'].append({
                        'url': record[0],
                        'timestamp': record[1],
                        'status': record[2],
                        'digest': record[3],
                        'length': record[4]
                    })
                return self.results['snapshots']
            return []
        except Exception as e:
            self.results['errors'].append(f"Historical records error: {str(e)}")
            return []

    def to_json(self):
        """Return results as JSON"""
        return json.dumps(self.results, indent=4)

    def save_report(self, output_dir='output'):
        """Save scan results to file"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = f"{output_dir}/wayback_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            f.write(self.to_json())

        return filename
