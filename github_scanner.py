#!/usr/bin/env python3
"""
GitHub Security Scanner
Scans GitHub organizations, users, and repositories for sensitive information
like API keys, tokens, passwords, and other secrets.
"""

import requests
import re
import time
import json
import argparse
from datetime import datetime
from typing import List, Dict, Set
import sys
from pathlib import Path

class GitHubScanner:
    def __init__(self, token: str = None, no_rate_limit: bool = False):
        """
        Initialize the GitHub scanner.
        
        Args:
            token: GitHub personal access token (optional but recommended)
            no_rate_limit: If True, disable rate limiting delays
        """
        self.token = token
        self.no_rate_limit = no_rate_limit
        self.session = requests.Session()
        
        if token:
            self.session.headers.update({
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json'
            })
        
        # Sensitive patterns to search for
        self.patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'aws_secret_access_key\s*=\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
            'GitHub Token': r'gh[pousr]_[A-Za-z0-9]{36,}',
            'Generic API Key': r'api[_-]?key\s*[:=]\s*[\'"]?([A-Za-z0-9_\-]{20,})[\'"]?',
            'Generic Secret': r'secret\s*[:=]\s*[\'"]?([A-Za-z0-9_\-]{20,})[\'"]?',
            'Password': r'password\s*[:=]\s*[\'"]?([^\s\'"]{8,})[\'"]?',
            'Private Key': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
            'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'Stripe Key': r'sk_live_[0-9a-zA-Z]{24,}',
            'Google API Key': r'AIza[0-9A-Za-z_\-]{35}',
            'Firebase URL': r'[a-z0-9.-]+\.firebaseio\.com',
            'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            'Heroku API Key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            'MailChimp API Key': r'[0-9a-f]{32}-us[0-9]{1,2}',
            'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
            'Telegram Bot Token': r'[0-9]{8,10}:[A-Za-z0-9_-]{35}',
            'Twilio API Key': r'SK[0-9a-fA-F]{32}',
            'PayPal/Braintree': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            'Square Access Token': r'sq0atp-[0-9A-Za-z\-_]{22}',
            'Square OAuth Secret': r'sq0csp-[0-9A-Za-z\-_]{43}',
            'Picatic API Key': r'sk_live_[0-9a-z]{32}',
            'NPM Token': r'npm_[A-Za-z0-9]{36}',
            'Docker Hub Token': r'dockerhub_[A-Za-z0-9]{36}',
            'JWT Token': r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
        }
        
        self.findings = []
        self.scanned_files = set()
        
    def add_custom_pattern(self, name: str, pattern: str):
        """Add a custom regex pattern to search for."""
        self.patterns[name] = pattern
    
    def check_rate_limit(self):
        """Check GitHub API rate limit status."""
        if not self.token:
            return
        
        response = self.session.get('https://api.github.com/rate_limit')
        if response.status_code == 200:
            data = response.json()
            core = data['resources']['core']
            print(f"[INFO] Rate limit: {core['remaining']}/{core['limit']} remaining")
            if core['remaining'] < 10:
                reset_time = datetime.fromtimestamp(core['reset'])
                print(f"[WARNING] Low rate limit. Resets at {reset_time}")
    
    def get_org_repos(self, org_name: str) -> List[Dict]:
        """Get all repositories for an organization."""
        repos = []
        page = 1
        
        while True:
            url = f'https://api.github.com/orgs/{org_name}/repos?page={page}&per_page=100'
            response = self.session.get(url)
            
            if response.status_code != 200:
                print(f"[ERROR] Failed to fetch repos for {org_name}: {response.status_code}")
                break
            
            data = response.json()
            if not data:
                break
            
            repos.extend(data)
            page += 1
            
            if not self.no_rate_limit:
                time.sleep(0.5)
        
        return repos
    
    def get_user_repos(self, username: str) -> List[Dict]:
        """Get all repositories for a user."""
        repos = []
        page = 1
        
        while True:
            url = f'https://api.github.com/users/{username}/repos?page={page}&per_page=100'
            response = self.session.get(url)
            
            if response.status_code != 200:
                print(f"[ERROR] Failed to fetch repos for {username}: {response.status_code}")
                break
            
            data = response.json()
            if not data:
                break
            
            repos.extend(data)
            page += 1
            
            if not self.no_rate_limit:
                time.sleep(0.5)
        
        return repos
    
    def get_repo_contents(self, owner: str, repo: str, path: str = "") -> List[Dict]:
        """Get contents of a repository directory."""
        url = f'https://api.github.com/repos/{owner}/{repo}/contents/{path}'
        response = self.session.get(url)
        
        if response.status_code != 200:
            return []
        
        return response.json()
    
    def scan_file_content(self, content: str, file_path: str, repo_name: str) -> List[Dict]:
        """Scan file content for sensitive patterns."""
        matches = []
        
        for pattern_name, pattern in self.patterns.items():
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                # Get line number
                line_num = content[:match.start()].count('\n') + 1
                
                # Get the matched text (truncate if too long)
                matched_text = match.group(0)
                if len(matched_text) > 100:
                    matched_text = matched_text[:100] + "..."
                
                matches.append({
                    'type': pattern_name,
                    'file': file_path,
                    'repo': repo_name,
                    'line': line_num,
                    'match': matched_text,
                    'timestamp': datetime.now().isoformat()
                })
        
        return matches
    
    def scan_file(self, owner: str, repo: str, file_info: Dict) -> List[Dict]:
        """Download and scan a single file."""
        file_path = file_info['path']
        
        # Skip if already scanned
        file_key = f"{owner}/{repo}/{file_path}"
        if file_key in self.scanned_files:
            return []
        
        self.scanned_files.add(file_key)
        
        # Skip binary files and very large files
        if file_info.get('size', 0) > 1000000:  # 1MB limit
            return []
        
        # Get file content
        response = self.session.get(file_info['download_url'])
        if response.status_code != 200:
            return []
        
        try:
            content = response.text
            return self.scan_file_content(content, file_path, f"{owner}/{repo}")
        except UnicodeDecodeError:
            # Skip binary files
            return []
    
    def scan_repo_recursive(self, owner: str, repo: str, path: str = ""):
        """Recursively scan all files in a repository."""
        contents = self.get_repo_contents(owner, repo, path)
        
        if not contents:
            return
        
        for item in contents:
            if item['type'] == 'file':
                print(f"  Scanning: {item['path']}")
                matches = self.scan_file(owner, repo, item)
                self.findings.extend(matches)
                
                if not self.no_rate_limit:
                    time.sleep(0.2)
                    
            elif item['type'] == 'dir':
                self.scan_repo_recursive(owner, repo, item['path'])
    
    def scan_repository(self, repo_info: Dict):
        """Scan a single repository."""
        owner = repo_info['owner']['login']
        repo = repo_info['name']
        
        print(f"\n[SCANNING] {owner}/{repo}")
        self.scan_repo_recursive(owner, repo)
    
    def scan_organization(self, org_name: str):
        """Scan all repositories in an organization."""
        print(f"\n[INFO] Fetching repositories for organization: {org_name}")
        repos = self.get_org_repos(org_name)
        
        print(f"[INFO] Found {len(repos)} repositories")
        
        for repo in repos:
            self.scan_repository(repo)
            self.check_rate_limit()
    
    def scan_user(self, username: str):
        """Scan all repositories for a user."""
        print(f"\n[INFO] Fetching repositories for user: {username}")
        repos = self.get_user_repos(username)
        
        print(f"[INFO] Found {len(repos)} repositories")
        
        for repo in repos:
            self.scan_repository(repo)
            self.check_rate_limit()
    
    def scan_single_repo(self, repo_url: str):
        """Scan a single repository by URL or owner/repo format."""
        # Parse repo URL
        if 'github.com/' in repo_url:
            parts = repo_url.split('github.com/')[-1].split('/')
            owner = parts[0]
            repo = parts[1].rstrip('.git')
        else:
            parts = repo_url.split('/')
            owner = parts[0]
            repo = parts[1]
        
        # Get repo info
        url = f'https://api.github.com/repos/{owner}/{repo}'
        response = self.session.get(url)
        
        if response.status_code != 200:
            print(f"[ERROR] Failed to fetch repository: {response.status_code}")
            return
        
        repo_info = response.json()
        self.scan_repository(repo_info)
    
    def generate_report(self, output_file: str = None):
        """Generate a report of findings."""
        if not self.findings:
            print("\n[SUCCESS] No sensitive information found!")
            return
        
        print(f"\n[ALERT] Found {len(self.findings)} potential sensitive items!")
        
        # Group by type
        by_type = {}
        for finding in self.findings:
            finding_type = finding['type']
            if finding_type not in by_type:
                by_type[finding_type] = []
            by_type[finding_type].append(finding)
        
        # Print summary
        print("\n" + "="*80)
        print("SCAN SUMMARY")
        print("="*80)
        for finding_type, items in sorted(by_type.items()):
            print(f"\n{finding_type}: {len(items)} findings")
            for item in items[:5]:  # Show first 5 of each type
                print(f"  - {item['repo']}/{item['file']}:{item['line']}")
                print(f"    Match: {item['match'][:80]}")
            if len(items) > 5:
                print(f"  ... and {len(items) - 5} more")
        
        # Save to file if requested
        if output_file:
            with open(output_file, 'w') as f:
                json.dump({
                    'scan_date': datetime.now().isoformat(),
                    'total_findings': len(self.findings),
                    'findings': self.findings,
                    'summary': {k: len(v) for k, v in by_type.items()}
                }, f, indent=2)
            print(f"\n[INFO] Full report saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='GitHub Security Scanner - Scan repositories for sensitive information',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan an organization
  python github_scanner.py --org facebook
  
  # Scan a user profile
  python github_scanner.py --user torvalds
  
  # Scan a specific repository
  python github_scanner.py --repo facebook/react
  
  # Use authentication token (recommended)
  python github_scanner.py --org facebook --token YOUR_GITHUB_TOKEN
  
  # Load patterns from config file
  python github_scanner.py --org facebook --config patterns_config.json
  
  # Add custom patterns
  python github_scanner.py --org myorg --custom-pattern "Company Secret" "SECRET_[A-Z0-9]+"
  
  # Disable rate limiting (use with caution)
  python github_scanner.py --org facebook --no-rate-limit
        """
    )
    
    parser.add_argument('--org', help='Organization name to scan')
    parser.add_argument('--user', help='Username to scan')
    parser.add_argument('--repo', help='Single repository to scan (format: owner/repo)')
    parser.add_argument('--token', help='GitHub personal access token')
    parser.add_argument('--output', '-o', help='Output file for results (JSON format)')
    parser.add_argument('--config', '-c', help='Load custom patterns from JSON config file')
    parser.add_argument('--no-rate-limit', action='store_true', 
                       help='Disable rate limiting delays (may hit API limits)')
    parser.add_argument('--custom-pattern', nargs=2, action='append',
                       metavar=('NAME', 'PATTERN'),
                       help='Add custom regex pattern (can be used multiple times)')
    
    args = parser.parse_args()
    
    if not any([args.org, args.user, args.repo]):
        parser.error('Must specify --org, --user, or --repo')
    
    # Initialize scanner
    scanner = GitHubScanner(token=args.token, no_rate_limit=args.no_rate_limit)
    
    # Load patterns from config file
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
                if 'custom_patterns' in config:
                    for name, pattern in config['custom_patterns'].items():
                        scanner.add_custom_pattern(name, pattern)
                    print(f"[INFO] Loaded {len(config['custom_patterns'])} patterns from config file")
        except Exception as e:
            print(f"[ERROR] Failed to load config file: {e}")
            sys.exit(1)
    
    # Add custom patterns from command line
    if args.custom_pattern:
        for name, pattern in args.custom_pattern:
            scanner.add_custom_pattern(name, pattern)
            print(f"[INFO] Added custom pattern: {name}")
    
    # Run scan
    try:
        if args.org:
            scanner.scan_organization(args.org)
        elif args.user:
            scanner.scan_user(args.user)
        elif args.repo:
            scanner.scan_single_repo(args.repo)
        
        # Generate report
        scanner.generate_report(args.output)
        
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Scan stopped by user")
        scanner.generate_report(args.output)
    except Exception as e:
        print(f"\n[ERROR] {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
