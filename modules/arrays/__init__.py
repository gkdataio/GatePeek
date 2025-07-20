# Arrays Package - Import all arrays for easy access
from .api_config import *
from .http_config import *
from .display_config import *
from .output_config import *
from .data_structures import *

# Explicitly import concurrency settings for better visibility
from .api_config import MAX_WORKERS, DNS_WORKERS, HTTP_WORKERS, GITHUB_WORKERS

# For backward compatibility - import everything from the old arrays.py location
__all__ = [
    # API Configuration
    'WAYBACK_API', 'SUBDOMAIN_CENTER_API', 'TIMEOUT', 'GITHUB_TOKEN',
    'GITHUB_MAX_PAGES', 'GITHUB_PER_PAGE', 'GITHUB_API_VERSION',
    
    # HTTP Configuration
    'HTTP_PROTOCOLS', 'BYPASS_STATUS_CODES', 'HTTP_METHODS', 'IMPORTANT_HEADERS',
    'BYPASS_PAYLOADS', 'BYPASS_PATHS', 'SSL_PORT',
    
    # Display Configuration
    'DISPLAY_HEADERS', 'FALSE_POSITIVE_INDICATORS', 'LIVE_INDICATORS',
    'RESPONSE_PREVIEW_LENGTH', 'HTML_PREVIEW_LINES', 'MIN_BOX_WIDTH', 'BOX_PADDING',
    
    # Output Configuration
    'RESULTS_DIR', 'JSON_INDENT', 'SUBDOMAIN_STATUSES', 'HTML_STATUS_CLASSES',
    
    # Data Structures
    'DEFAULT_SUMMARY_STRUCTURE', 'SUBDOMAIN_DATA_STRUCTURE', 
    'HTTP_METHOD_RESULT_STRUCTURE', 'SSL_INFO_STRUCTURE'
] 