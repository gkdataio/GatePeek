# GitHub URL Parser Module
# This module handles parsing GitHub URLs to extract repository information

import re
from urllib.parse import urlparse

class GitHubURLParser:
    """Parser for GitHub URLs to extract repository and file information"""
    
    @staticmethod
    def parse_github_url(url):
        """Parse a GitHub URL to extract repository, branch, and file information"""
        try:
            # Parse the URL
            parsed = urlparse(url)
            
            # Extract path components
            path_parts = parsed.path.strip('/').split('/')
            
            if len(path_parts) < 3:
                return None
            
            # Extract repository information
            owner = path_parts[0]
            repo = path_parts[1]
            branch = path_parts[3] if len(path_parts) > 3 else "main"
            
            # Extract file path
            file_path = '/'.join(path_parts[4:]) if len(path_parts) > 4 else ""
            
            # Extract line number from fragment
            line_number = None
            if parsed.fragment and parsed.fragment.startswith('L'):
                try:
                    line_number = int(parsed.fragment[1:])
                except ValueError:
                    pass
            
            return {
                'owner': owner,
                'repository': repo,
                'branch': branch,
                'file_path': file_path,
                'line_number': line_number,
                'full_url': url,
                'repository_url': f"https://github.com/{owner}/{repo}"
            }
        except Exception as e:
            return None
    
    @staticmethod
    def extract_repository_info(urls):
        """Extract repository information from a list of GitHub URLs"""
        repositories = {}
        
        for url in urls:
            info = GitHubURLParser.parse_github_url(url)
            if info:
                repo_key = f"{info['owner']}/{info['repository']}"
                if repo_key not in repositories:
                    repositories[repo_key] = {
                        'owner': info['owner'],
                        'repository': info['repository'],
                        'repository_url': info['repository_url'],
                        'files': [],
                        'total_references': 0
                    }
                
                repositories[repo_key]['files'].append({
                    'file_path': info['file_path'],
                    'line_number': info['line_number'],
                    'url': url
                })
                repositories[repo_key]['total_references'] += 1
        
        return repositories
    
    @staticmethod
    def format_github_context(subdomain, urls):
        """Format GitHub context information for a subdomain"""
        if not urls:
            return None
        
        # Parse all URLs
        parsed_urls = [GitHubURLParser.parse_github_url(url) for url in urls]
        parsed_urls = [url for url in parsed_urls if url]
        
        if not parsed_urls:
            return None
        
        # Extract unique repositories
        repositories = GitHubURLParser.extract_repository_info(urls)
        
        # Get line numbers
        line_numbers = []
        for url in urls:
            info = GitHubURLParser.parse_github_url(url)
            if info and info['line_number']:
                line_numbers.append(info['line_number'])
        
        # Get unique file paths
        file_paths = list(set([url['file_path'] for url in parsed_urls if url['file_path']]))
        
        return {
            'subdomain': subdomain,
            'source_urls': urls,
            'line_numbers': sorted(list(set(line_numbers))),
            'file_paths': sorted(file_paths),
            'repositories': repositories,
            'total_references': len(urls),
            'unique_repositories': len(repositories)
        } 