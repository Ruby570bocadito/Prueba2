import requests
import base64
import json
import os
import re
from datetime import datetime
from urllib.parse import urlparse

class GitHubScanner:
    def __init__(self, api_token=None):
        self.api_token = api_token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Accept": "application/vnd.github.v3+json"
        }
        if api_token:
            self.headers["Authorization"] = f"token {api_token}"
        
        self.results = {
            'repositories': [],
            'commits': [],
            'code_search': [],
            'errors': []
        }

    def search_repositories(self, query, sort='updated', order='desc'):
        """Search GitHub repositories"""
        try:
            params = {
                'q': query,
                'sort': sort,
                'order': order
            }
            response = requests.get(
                f"{self.base_url}/search/repositories",
                headers=self.headers,
                params=params
            )
            response.raise_for_status()
            
            results = response.json()
            self.results['repositories'].extend(results.get('items', []))
            return results.get('items', [])
        except Exception as e:
            self.results['errors'].append(f"Repository search error: {str(e)}")
            return []

    def search_code(self, query, sort='indexed', order='desc'):
        """Search code on GitHub"""
        try:
            params = {
                'q': query,
                'sort': sort,
                'order': order
            }
            response = requests.get(
                f"{self.base_url}/search/code",
                headers=self.headers,
                params=params
            )
            response.raise_for_status()
            
            results = response.json()
            self.results['code_search'].extend(results.get('items', []))
            return results.get('items', [])
        except Exception as e:
            self.results['errors'].append(f"Code search error: {str(e)}")
            return []

    def get_repository_content(self, owner, repo, path=''):
        """Get contents of a repository path"""
        try:
            response = requests.get(
                f"{self.base_url}/repos/{owner}/{repo}/contents/{path}",
                headers=self.headers
            )
            response.raise_for_status()
            
            content = response.json()
            if isinstance(content, dict) and content.get('type') == 'file':
                if content.get('encoding') == 'base64':
                    content['decoded_content'] = base64.b64decode(content['content']).decode('utf-8')
            return content
        except Exception as e:
            self.results['errors'].append(f"Content fetch error: {str(e)}")
            return None

    def get_commit_history(self, owner, repo, path='', since=None):
        """Get commit history for a repository or path"""
        try:
            params = {}
            if path:
                params['path'] = path
            if since:
                params['since'] = since.isoformat()
                
            response = requests.get(
                f"{self.base_url}/repos/{owner}/{repo}/commits",
                headers=self.headers,
                params=params
            )
            response.raise_for_status()
            
            commits = response.json()
            self.results['commits'].extend(commits)
            return commits
        except Exception as e:
            self.results['errors'].append(f"Commit history error: {str(e)}")
            return []

    def find_sensitive_data(self, owner, repo):
        """Search for potentially sensitive data in a repository"""
        sensitive_patterns = {
            'aws_keys': r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])',
            'aws_secrets': r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
            'api_keys': r'(?i)(api|key|token|secret)[_-]?key[=:]\s*([a-z0-9]{32,})',
            'database_urls': r'(?i)(postgres|mysql|mongodb)://[a-z0-9_-]+:[^@\s]+@[a-z0-9.-]+',
            'config_files': r'(\.env|config\.json|settings\.py|credentials)'
        }
        
        findings = []
        try:
            # Search repository code
            code_results = self.search_code(f"repo:{owner}/{repo}")
            for item in code_results:
                content = self.get_repository_content(item['repository']['owner']['login'], 
                                                    item['repository']['name'], 
                                                    item['path'])
                if content and 'decoded_content' in content:
                    text = content['decoded_content']
                    for pattern_name, pattern in sensitive_patterns.items():
                        matches = re.findall(pattern, text)
                        if matches:
                            findings.append({
                                'file': item['path'],
                                'pattern': pattern_name,
                                'matches': matches,
                                'html_url': item['html_url']
                            })
        except Exception as e:
            self.results['errors'].append(f"Sensitive data scan error: {str(e)}")
        
        return findings

    def to_json(self):
        """Return results as JSON"""
        return json.dumps(self.results, indent=4)

    def save_report(self, output_dir='output'):
        """Save scan results to file"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = f"{output_dir}/github_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            f.write(self.to_json())

        return filename
