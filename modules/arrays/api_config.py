# API Configuration Arrays
# This module contains all API-related configuration arrays and settings

import os

# API Endpoints
WAYBACK_API = "https://web.archive.org/cdx/search/cdx"
SUBDOMAIN_CENTER_API = "https://api.subdomain.center/"

# Request Timeouts (seconds) - tuned per operation type
DNS_TIMEOUT = 8        # DNS resolution
HTTP_TIMEOUT = 10      # Standard HTTP requests
GITHUB_TIMEOUT = 15    # GitHub API / raw content fetches
SSL_TIMEOUT = 8        # SSL handshake

# Legacy alias used throughout the codebase
TIMEOUT = HTTP_TIMEOUT

# GitHub API Configuration
# Set the GITHUB_TOKEN environment variable for authenticated requests.
# Unauthenticated: 60 req/hr  |  Authenticated: 5,000 req/hr
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_MAX_PAGES = 3
GITHUB_PER_PAGE = 100
GITHUB_API_VERSION = "2022-11-28"

# Concurrency Settings
MAX_WORKERS = 10
DNS_WORKERS = 15
HTTP_WORKERS = 20
GITHUB_WORKERS = 5
