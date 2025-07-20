# HTTP Configuration Arrays
# This module contains all HTTP-related configuration arrays and settings

# HTTP Protocols for testing
HTTP_PROTOCOLS = ["http://", "https://"]

# HTTP Status Codes for bypass detection
BYPASS_STATUS_CODES = [403, 401]

# HTTP Methods to test
HTTP_METHODS = ['OPTIONS', 'TRACE', 'PUT', 'POST']

# Important HTTP Headers to capture
IMPORTANT_HEADERS = [
    'Server', 
    'X-Powered-By', 
    'Allow', 
    'Content-Type', 
    'Content-Length', 
    'Location', 
    'WWW-Authenticate',
    'X-Frame-Options', 
    'X-Content-Type-Options',
    'Strict-Transport-Security', 
    'Content-Security-Policy'
]

# 403 Bypass Payloads (Header-based)
BYPASS_PAYLOADS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"X-Original-URL": "/"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Real-IP": "127.0.0.1"},
    {"Host": "127.0.0.1"},
    {"Referer": "https://{subdomain}/admin"},
]

# 403 Bypass Paths (Path-based)
BYPASS_PATHS = [
    # Common admin paths
    "/admin",
    "/administrator",
    "/admin.php",
    "/admin.html",
    "/admin/",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/cpanel",
    "/webmail",
    "/mail",
    "/ftp",
    "/ssh",
    "/telnet",
    
    # API and development paths
    "/api",
    "/api/v1",
    "/api/v2",
    "/rest",
    "/graphql",
    "/swagger",
    "/docs",
    "/documentation",
    "/test",
    "/dev",
    "/staging",
    "/beta",
    "/debug",
    "/status",
    "/health",
    "/ping",
    "/info",
    "/version",
    
    # Configuration and system files
    "/config",
    "/.env",
    "/.git",
    "/.svn",
    "/.htaccess",
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
    "/.well-known/security.txt",
    "/.well-known/host-meta",
    "/.well-known/webfinger",
    
    # Path traversal and encoding bypasses
    "/..;/",
    "/%2e/",
    "/%2e%2e/",
    "/%2e%2e%2f",
    "/%2e%2e/",
    "/..%2f",
    "/..%5c",
    "/%2e%2e%5c",
    "/..%255c",
    "/..%c0%af",
    "/..%c1%9c",
    
    # Common file extensions
    "/.json",
    "/.xml",
    "/.txt",
    "/.log",
    "/.bak",
    "/.backup",
    "/.old",
    "/.tmp",
    "/.temp",
    
    # Web application paths
    "/index.php",
    "/index.html",
    "/login",
    "/logout",
    "/register",
    "/signup",
    "/signin",
    "/dashboard",
    "/panel",
    "/console",
    "/manager",
    "/manage",
    "/control",
    "/settings",
    "/profile",
    "/user",
    "/users",
    "/account",
    "/accounts",
    
    # CMS and framework paths
    "/wp-content",
    "/wp-includes",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.php.backup",
    "/wp-config.php.tmp",
    "/wp-config.php.temp",
    "/wp-config.php.txt",
    "/wp-config.php.log",
    "/wp-config.php.xml",
    "/wp-config.php.json",
    
    # Database and backend paths
    "/db",
    "/database",
    "/sql",
    "/mysql",
    "/postgres",
    "/mongodb",
    "/redis",
    "/memcached",
    "/cache",
    "/session",
    "/sessions",
    "/auth",
    "/authentication",
    "/authorization",
    
    # Monitoring and logging paths
    "/monitor",
    "/monitoring",
    "/logs",
    "/log",
    "/error",
    "/errors",
    "/debug",
    "/debugging",
    "/trace",
    "/tracing",
    "/profiler",
    "/profiling",
    
    # Service discovery paths
    "/discovery",
    "/service",
    "/services",
    "/endpoint",
    "/endpoints",
    "/resource",
    "/resources",
    "/data",
    "/api-docs",
    "/openapi",
    "/swagger-ui",
    "/redoc",
    
    # Security and compliance paths
    "/security",
    "/compliance",
    "/audit",
    "/auditing",
    "/scan",
    "/scanning",
    "/vulnerability",
    "/vulnerabilities",
    "/threat",
    "/threats",
    "/risk",
    "/risks"
]

# SSL Settings
SSL_PORT = 443 