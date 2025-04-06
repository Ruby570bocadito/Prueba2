import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import requests
import json
import os
from datetime import datetime
import re

class BucketScanner:
    def __init__(self):
        self.results = {
            'buckets': [],
            'errors': []
        }
        self.public_permissions = [
            'READ', 'WRITE', 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL'
        ]

    def check_bucket_permissions(self, bucket_name):
        """Check permissions for a specific S3 bucket"""
        try:
            s3 = boto3.client('s3')
            
            # Check bucket existence
            try:
                s3.head_bucket(Bucket=bucket_name)
            except ClientError as e:
                if e.response['Error']['Code'] == '404':
                    self.results['errors'].append(f"Bucket {bucket_name} does not exist")
                    return
                elif e.response['Error']['Code'] == '403':
                    self.results['errors'].append(f"Access denied to bucket {bucket_name}")
                    return
                else:
                    raise

            # Check bucket ACL
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            public_grants = [
                grant for grant in acl['Grants']
                if 'URI' in grant['Grantee'] and 
                grant['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers'
            ]

            # Check bucket policy
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_doc = json.loads(policy['Policy'])
                self._analyze_policy(policy_doc, bucket_name)
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    self.results['errors'].append(f"Error checking bucket policy: {str(e)}")

            # Check if bucket is publicly accessible
            try:
                url = f"http://{bucket_name}.s3.amazonaws.com"
                r = requests.head(url, timeout=5)
                is_public = r.status_code == 200
            except:
                is_public = False

            bucket_result = {
                'name': bucket_name,
                'exists': True,
                'public': is_public,
                'public_permissions': [g['Permission'] for g in public_grants],
                'objects': []
            }

            # List objects if bucket is public
            if is_public:
                try:
                    objects = s3.list_objects_v2(Bucket=bucket_name)
                    if 'Contents' in objects:
                        bucket_result['objects'] = [
                            {'key': obj['Key'], 'size': obj['Size']} 
                            for obj in objects['Contents']
                        ]
                except ClientError as e:
                    self.results['errors'].append(f"Error listing objects: {str(e)}")

            self.results['buckets'].append(bucket_result)

        except NoCredentialsError:
            self.results['errors'].append("AWS credentials not configured")
        except Exception as e:
            self.results['errors'].append(f"Error scanning bucket {bucket_name}: {str(e)}")

    def _analyze_policy(self, policy_doc, bucket_name):
        """Analyze bucket policy for public access"""
        for statement in policy_doc.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal', {})
                if principal == '*' or (isinstance(principal, dict) and 'AWS' in principal and principal['AWS'] == '*'):
                    self.results['buckets'].append({
                        'name': bucket_name,
                        'policy_public': True,
                        'policy_actions': statement.get('Action', []),
                        'policy_resources': statement.get('Resource', [])
                    })

    def scan_buckets(self, bucket_names):
        """Scan multiple S3 buckets"""
        for name in bucket_names:
            self.check_bucket_permissions(name)

    def find_buckets_by_domain(self, domain):
        """Find potential S3 buckets based on domain name"""
        common_prefixes = [
            '',
            'www',
            'assets',
            'static',
            'media',
            'uploads',
            'backup',
            'backups',
            'storage',
            'data'
        ]

        bucket_candidates = [
            f"{prefix}-{domain}" if prefix else domain
            for prefix in common_prefixes
        ] + [
            f"{domain}-{suffix}"
            for suffix in ['dev', 'prod', 'stage', 'test', 'archive']
        ]

        for candidate in bucket_candidates:
            candidate = re.sub(r'[^a-z0-9\-]', '', candidate.lower())
            if len(candidate) > 3:  # Minimum bucket name length
                self.check_bucket_permissions(candidate)

    def to_json(self):
        """Return results as JSON"""
        return json.dumps(self.results, indent=4)

    def save_report(self, output_dir='output'):
        """Save scan results to file"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = f"{output_dir}/bucket_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            f.write(self.to_json())

        return filename
