# Display Configuration Arrays
# This module contains all display-related configuration arrays and settings

# Headers to display in results
DISPLAY_HEADERS = ["Server", "Content-Type", "Location"]

# False Positive Indicators for Response Classification
FALSE_POSITIVE_INDICATORS = [
    "403 forbidden",
    "access denied",
    "nginx",
    "apache",
    "cloudflare",
    "forbidden",
    "unauthorized",
    "not found",
    "bad gateway",
    "service unavailable"
]

# Live Indicators for Response Classification
LIVE_INDICATORS = [
    "html",
    "json",
    "xml",
    "javascript",
    "css",
    "text/plain",
    "application/json",
    "text/html"
]

# Response Preview Settings
RESPONSE_PREVIEW_LENGTH = 200
HTML_PREVIEW_LINES = 5

# Box Display Settings
MIN_BOX_WIDTH = 60
BOX_PADDING = 10 