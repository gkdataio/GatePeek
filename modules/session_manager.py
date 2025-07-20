# Session Manager Module
# This module handles HTTP sessions and connection pooling for better performance

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from modules.arrays import TIMEOUT

class SessionManager:
    """Manages HTTP sessions with connection pooling and retry logic"""
    
    def __init__(self):
        self.session = self._create_session()
    
    def _create_session(self):
        """Create a requests session with optimized settings"""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        # Configure adapter with connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,
            pool_maxsize=20
        )
        
        # Mount adapters for both HTTP and HTTPS
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            'User-Agent': 'SubdomainRecon/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        return session
    
    def get(self, url, **kwargs):
        """Make a GET request with the session"""
        kwargs.setdefault('timeout', TIMEOUT)
        kwargs.setdefault('verify', False)
        kwargs.setdefault('allow_redirects', True)
        return self.session.get(url, **kwargs)
    
    def request(self, method, url, **kwargs):
        """Make a request with the session"""
        kwargs.setdefault('timeout', TIMEOUT)
        kwargs.setdefault('verify', False)
        kwargs.setdefault('allow_redirects', True)
        return self.session.request(method, url, **kwargs)
    
    def close(self):
        """Close the session"""
        self.session.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close() 