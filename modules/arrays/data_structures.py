# Data Structures
# This module contains all data structure templates and schemas

# Default Summary Structure
DEFAULT_SUMMARY_STRUCTURE = {
    "domain": "",
    "scan_date": "",
    "total_subdomains": 0,
    "live": [],
    "false_positive": [],
    "ambiguous": [],
    "live_count": 0,
    "false_positive_count": 0,
    "ambiguous_count": 0
}

# Subdomain Data Structure
SUBDOMAIN_DATA_STRUCTURE = {
    "subdomain": "",
    "ip": "",
    "status": None,
    "headers": {},
    "verdict": "",
    "bypass": None,
    "ssl_info": None,
    "http_methods": {},
    "github_context": None,
    "sources": []
}

# HTTP Method Result Structure
HTTP_METHOD_RESULT_STRUCTURE = {
    "status": None,
    "headers": {},
    "response_preview": "",
    "content_length": 0,
    "content_type": "",
    "error": None
}

# SSL Info Structure
SSL_INFO_STRUCTURE = {
    "subject": {},
    "issuer": {},
    "valid_from": "",
    "valid_until": ""
}

# GitHub Context Structure
GITHUB_CONTEXT_STRUCTURE = {
    "subdomain": "",
    "source_urls": [],
    "line_numbers": [],
    "file_paths": [],
    "repository": "",
    "branch": ""
} 