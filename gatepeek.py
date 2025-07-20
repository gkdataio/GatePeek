import requests
import socket
import re
import time
from colorama import Fore, Style, init
from datetime import datetime
import os
import textwrap
import json
import subprocess
import ssl
import OpenSSL.crypto
import html
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.arrays import *
from modules.arrays.api_config import MAX_WORKERS, DNS_WORKERS, HTTP_WORKERS, GITHUB_WORKERS
from modules.html_generator import HTMLReportGenerator

init(autoreset=True)

# =============================================================================
# GATEPEEK BANNER
# =============================================================================
# Paste your ASCII banner here for Gatepeek - see beyond the gate @gkdata
# =============================================================================

def display_banner():
    """Display the Gatepeek banner"""
    banner = f"""
{Fore.CYAN}
{Fore.CYAN} _______  _______ _________ _______  _______  _______  _______  _       
{Fore.CYAN}(  ____ \\(  ___  )\\__   __/(  ____ \\(  ____ )(  ____ \\(  ____ \\| \\    /\\
{Fore.CYAN}| (    \\/| (   ) |   ) (   | (    \\/| (    )|| (    \\/| (    \\/|  \\  / /
{Fore.CYAN}| |      | (___) |   | |   | (__    | (____)|| (__    | (__    |  (_/ / 
{Fore.CYAN}| | ____ |  ___  |   | |   |  __)   |  _____)|  __)   |  __)   |   _ (  
{Fore.CYAN}| | \\_  )| (   ) |   | |   | (      | (      | (      | (      |  ( \\ \\ 
{Fore.CYAN}| (___) || )   ( |   | |   | (____/\\| )      | (____/\\| (____/\\|  /  \\ \\
{Fore.CYAN}(_______)|/     \\|   )_(   (_______/|/       (_______/(_______/|_/    \\/
{Fore.CYAN}
{Fore.CYAN}                        see beyond the gate
{Fore.CYAN}
{Fore.CYAN}                              @gkdata
{Fore.RESET}
"""
    print(banner)



def get_subdomains_wayback(domain):
    print(f"{Fore.BLUE}[*] Pulling from Wayback Machine...")
    try:
        params = {
            "url": f"*.{domain}",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey"
        }
        
        # Use a shorter timeout for Wayback API to prevent hanging
        r = requests.get(WAYBACK_API, params=params, timeout=15, verify=True)
        
        if r.status_code == 200:
            data = r.json()
            if not data or len(data) < 2:
                print(f"{Fore.YELLOW}[!] No Wayback data found for {domain}")
                return set()
            
            subdomains = set()
            for entry in data[1:]:  # Skip the first entry (header)
                if entry and len(entry) > 0:
                    try:
                        host = entry[0].split("//")[-1].split("/")[0]
                        if domain in host:
                            subdomains.add(host.lower())
                    except (IndexError, AttributeError):
                        continue
            
            print(f"{Fore.GREEN}[+] Found {len(subdomains)} subdomains from Wayback Machine")
            return subdomains
        else:
            print(f"{Fore.RED}[-] Wayback API returned status {r.status_code}")
            return set()
            
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}[-] Wayback API timeout - skipping")
        return set()
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[-] Wayback API connection error - skipping")
        return set()
    except Exception as e:
        print(f"{Fore.RED}[-] Wayback error: {e}")
        return set()

def get_subdomains_center(domain):
    print(f"{Fore.BLUE}[*] Pulling from Subdomain Center...")
    try:
        r = requests.get(SUBDOMAIN_CENTER_API, params={"domain": domain}, timeout=15, verify=True)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict) and "subdomains" in data:
                subdomains = set(d.lower() for d in data["subdomains"])
                print(f"{Fore.GREEN}[+] Found {len(subdomains)} subdomains from Subdomain Center")
                return subdomains
            elif isinstance(data, list):
                subdomains = set(d.lower() for d in data)
                print(f"{Fore.GREEN}[+] Found {len(subdomains)} subdomains from Subdomain Center")
                return subdomains
            else:
                print(f"{Fore.YELLOW}[!] No Subdomain Center data found for {domain}")
                return set()
        else:
            print(f"{Fore.RED}[-] Subdomain Center API returned status {r.status_code}")
            return set()
    except requests.exceptions.Timeout:
        print(f"{Fore.RED}[-] Subdomain Center API timeout - skipping")
        return set()
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[-] Subdomain Center API connection error - skipping")
        return set()
    except Exception as e:
        print(f"{Fore.RED}[-] Subdomain Center error: {e}")
        return set()

def fetch_github_page(domain, page, headers):
    """Fetch a single GitHub page for subdomain discovery"""
    q = f"{domain}+in:file"
    url = f"https://api.github.com/search/code?q={q}&per_page={GITHUB_PER_PAGE}&page={page}"
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        if r.status_code == 403:
            return None, "rate_limit"
        elif r.status_code != 200:
            return None, f"error_{r.status_code}"
        
        items = r.json().get("items", [])
        if not items:
            return [], "no_items"
        
        return items, "success"
    except Exception as e:
        return None, f"exception_{str(e)}"

def process_github_item(item, domain):
    """Process a single GitHub item to extract subdomains with line-level context"""
    html_url = item.get("html_url", "")
    raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    
    try:
        code = requests.get(raw_url, timeout=10).text  # Shorter timeout for raw content
        found = {}
        
        # Process each line to get line numbers
        for idx, line in enumerate(code.splitlines(), 1):
            if domain in line:
                matches = re.findall(rf"(?:https?://)?([\w\.-]+\.{re.escape(domain)})", line)
                for match in matches:
                    match_lower = match.lower()
                    if match_lower not in found:
                        found[match_lower] = []
                    found[match_lower].append(f"{html_url}#L{idx}")
        
        return found
    except Exception as e:
        print(f"{Fore.RED}[!] Error processing GitHub item: {e}")
        return {}

def get_subdomains_github(domain, max_pages=GITHUB_MAX_PAGES):
    """Get subdomains from GitHub using parallel processing with line-level context"""
    print(f"{Fore.BLUE}[*] Pulling from GitHub code search...")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": GITHUB_API_VERSION
    }
    
    found = {}  # Changed from set() to dict() to store context
    
    # Fetch GitHub pages in parallel
    with ThreadPoolExecutor(max_workers=GITHUB_WORKERS) as executor:
        # Submit all page fetch tasks
        future_to_page = {
            executor.submit(fetch_github_page, domain, page, headers): page 
            for page in range(1, max_pages + 1)
        }
        
        # Process completed page fetches
        for future in as_completed(future_to_page):
            page = future_to_page[future]
            try:
                items, status = future.result()
                
                if status == "rate_limit":
                    print(f"{Fore.RED}[!] GitHub rate limit hit on page {page}.")
                    break
                elif status.startswith("error_"):
                    print(f"{Fore.RED}[!] GitHub error on page {page}: {status}")
                    break
                elif status == "no_items":
                    print(f"{Fore.YELLOW}[!] No items found on page {page}.")
                    break
                elif status.startswith("exception_"):
                    print(f"{Fore.RED}[!] GitHub exception on page {page}: {status}")
                    continue
                
                if not items:
                    continue
                
                # Process items in parallel
                item_futures = {
                    executor.submit(process_github_item, item, domain): item 
                    for item in items
                }
                
                for item_future in as_completed(item_futures):
                    try:
                        subdomain_contexts = item_future.result()
                        # Merge subdomain contexts
                        for subdomain, contexts in subdomain_contexts.items():
                            if subdomain not in found:
                                found[subdomain] = []
                            found[subdomain].extend(contexts)
                    except Exception as e:
                        continue
                        
            except Exception as e:
                print(f"{Fore.RED}[!] Error processing page {page}: {e}")
                continue
    
    print(f"{Fore.GREEN}[+] Found {len(found)} subdomains from GitHub")
    return found

def resolve_ip(sub):
    """Resolve IP address for a subdomain"""
    try:
        return socket.gethostbyname(sub)
    except:
        return None

def resolve_ips_parallel(subdomains):
    """Resolve IP addresses for multiple subdomains in parallel"""
    print(f"{Fore.BLUE}[*] Resolving IP addresses for {len(subdomains)} subdomains...")
    
    resolved = {}
    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as executor:
        # Submit all DNS resolution tasks
        future_to_subdomain = {executor.submit(resolve_ip, sub): sub for sub in subdomains}
        
        # Process completed tasks
        for future in as_completed(future_to_subdomain):
            subdomain = future_to_subdomain[future]
            try:
                ip = future.result()
                if ip:
                    resolved[subdomain] = ip
                    print(f"{Fore.GREEN}[+] {subdomain} -> {ip}")
                else:
                    print(f"{Fore.RED}[-] {subdomain} -> Could not resolve")
            except Exception as e:
                print(f"{Fore.RED}[-] {subdomain} -> Error: {e}")
    
    return resolved

def check_http(sub, session_manager=None):
    """Check HTTP response for a subdomain"""
    if session_manager is None:
        # Fallback to regular requests if no session provided
        for proto in HTTP_PROTOCOLS:
            try:
                r = requests.get(proto + sub, timeout=TIMEOUT, allow_redirects=True, verify=False)
                return r.status_code, dict(r.headers), r.text
            except:
                continue
        return None, {}, ""
    
    # Use session manager for better performance
    for proto in HTTP_PROTOCOLS:
        try:
            r = session_manager.get(proto + sub)
            return r.status_code, dict(r.headers), r.text
        except:
            continue
    return None, {}, ""

def check_http_parallel(subdomain_ip_pairs, session_manager=None):
    """Check HTTP responses for multiple subdomains in parallel"""
    print(f"{Fore.BLUE}[*] Checking HTTP responses for {len(subdomain_ip_pairs)} subdomains...")
    
    results = {}
    with ThreadPoolExecutor(max_workers=HTTP_WORKERS) as executor:
        # Submit all HTTP checking tasks
        future_to_subdomain = {
            executor.submit(check_http, subdomain, session_manager): subdomain 
            for subdomain in subdomain_ip_pairs.keys()
        }
        
        # Process completed tasks
        for future in as_completed(future_to_subdomain):
            subdomain = future_to_subdomain[future]
            try:
                status, headers, body = future.result()
                results[subdomain] = {
                    'status': status,
                    'headers': headers,
                    'body': body,
                    'ip': subdomain_ip_pairs[subdomain]
                }
                
                # Print status
                if status:
                    print(f"{Fore.GREEN}[+] {subdomain} -> HTTP {status}")
                else:
                    print(f"{Fore.RED}[-] {subdomain} -> No HTTP response")
                    
            except Exception as e:
                print(f"{Fore.RED}[-] {subdomain} -> Error: {e}")
                results[subdomain] = {
                    'status': None,
                    'headers': {},
                    'body': '',
                    'ip': subdomain_ip_pairs[subdomain]
                }
    
    return results

def bypass_403(sub, session_manager=None):
    """Attempt to bypass 403/401 errors using headers and paths"""
    base_url = f"https://{sub}"
    
    # Try header-based bypasses first
    payloads = BYPASS_PAYLOADS.copy()
    # Replace placeholder with actual subdomain
    for payload in payloads:
        if "Referer" in payload:
            payload["Referer"] = payload["Referer"].format(subdomain=sub)
    
    for headers in payloads:
        try:
            if session_manager:
                r = session_manager.get(base_url, headers=headers)
            else:
                r = requests.get(base_url, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=True)
            
            if r.status_code not in BYPASS_STATUS_CODES:
                return r.status_code, dict(r.headers), {"bypass_type": "header", "headers": headers}, r.text
        except:
            continue
    
    # Try path-based bypasses
    for path in BYPASS_PATHS:
        try:
            path_url = f"{base_url}{path}"
            if session_manager:
                r = session_manager.get(path_url)
            else:
                r = requests.get(path_url, timeout=TIMEOUT, verify=False, allow_redirects=True)
            
            if r.status_code not in BYPASS_STATUS_CODES:
                return r.status_code, dict(r.headers), {"bypass_type": "path", "path": path}, r.text
        except:
            continue
    
    # Try combination of headers and paths
    for path in BYPASS_PATHS[:10]:  # Limit to first 10 paths for combinations
        for headers in payloads[:5]:  # Limit to first 5 headers for combinations
            try:
                path_url = f"{base_url}{path}"
                if session_manager:
                    r = session_manager.get(path_url, headers=headers)
                else:
                    r = requests.get(path_url, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=True)
                
                if r.status_code not in BYPASS_STATUS_CODES:
                    return r.status_code, dict(r.headers), {"bypass_type": "combination", "path": path, "headers": headers}, r.text
            except:
                continue
    
    return None, {}, None, ""

def classify_response(body, status_code, headers):
    b = body.lower()
    h = {k.lower(): v.lower() for k, v in headers.items()}
    
    # If we have a successful status code, it's likely live
    if status_code and 200 <= status_code < 400:
        return SUBDOMAIN_STATUSES["live"]
    
    # Check headers for content type
    content_type = h.get('content-type', '')
    if any(indicator in content_type for indicator in LIVE_INDICATORS):
        return SUBDOMAIN_STATUSES["live"]
    
    # Check body for false positive indicators
    if any(indicator in b for indicator in FALSE_POSITIVE_INDICATORS):
        return SUBDOMAIN_STATUSES["false_positive"]
    
    # If body is too small, it's ambiguous
    if len(body) < 100:
        return SUBDOMAIN_STATUSES["ambiguous"]
    
    return SUBDOMAIN_STATUSES["live"]

def get_ssl_info(ip, domain):
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect to the server
        with socket.create_connection((ip, SSL_PORT), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                
                # Extract certificate information
                subject = dict(x509.get_subject().get_components())
                issuer = dict(x509.get_issuer().get_components())
                
                # Format dates
                not_before = datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
                not_after = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                
                return {
                    'subject': {k.decode(): v.decode() for k, v in subject.items()},
                    'issuer': {k.decode(): v.decode() for k, v in issuer.items()},
                    'valid_from': not_before.strftime('%Y-%m-%d %H:%M:%S'),
                    'valid_until': not_after.strftime('%Y-%m-%d %H:%M:%S')
                }
    except Exception as e:
        return None

def test_http_methods(sub, ip, session_manager=None):
    """Test various HTTP methods on a subdomain"""
    methods = HTTP_METHODS
    results = {}
    important_headers = IMPORTANT_HEADERS
    
    for method in methods:
        try:
            if session_manager:
                r = session_manager.request(method, f"https://{sub}")
            else:
                r = requests.request(
                    method,
                    f"https://{sub}",
                    timeout=TIMEOUT,
                    verify=False,
                    allow_redirects=True
                )
            
            # Get important headers
            headers_info = {}
            for header in important_headers:
                if header in r.headers:
                    headers_info[header] = r.headers[header]
            
            # Get response preview (first 200 chars)
            response_text = r.text if r.text else ''
            response_preview = response_text[:RESPONSE_PREVIEW_LENGTH]
            if len(response_text) > RESPONSE_PREVIEW_LENGTH:
                response_preview += "..."
            
            # Try to detect content type
            content_type = r.headers.get('Content-Type', '').lower()
            is_json = 'application/json' in content_type
            is_html = 'text/html' in content_type
            
            # Format response based on content type
            if is_json:
                try:
                    json_response = r.json()
                    response_preview = json.dumps(json_response, indent=2)[:RESPONSE_PREVIEW_LENGTH]
                    if len(json.dumps(json_response)) > RESPONSE_PREVIEW_LENGTH:
                        response_preview += "..."
                except:
                    pass
            elif is_html:
                # For HTML, show the first few lines
                response_preview = '\n'.join(response_text.split('\n')[:HTML_PREVIEW_LINES])
                if len(response_text.split('\n')) > HTML_PREVIEW_LINES:
                    response_preview += "\n..."
            
            results[method] = {
                'status': r.status_code,
                'headers': headers_info,
                'response_preview': response_preview,
                'content_length': len(response_text),
                'content_type': content_type
            }
        except Exception as e:
            results[method] = {
                'status': None,
                'error': str(e)
            }
    
    return results

def print_result_box(sub, ip, status, headers, body, bypass=None, session_manager=None, github_context=None):
    verdict = classify_response(body, status, headers)
    color = Fore.GREEN if verdict == "live" else Fore.YELLOW if verdict == "ambiguous" else Fore.RED
    
    # Get SSL information
    ssl_info = get_ssl_info(ip, sub)
    
    # Test HTTP methods
    method_results = test_http_methods(sub, ip, session_manager)
    
    # Create a box with dynamic width based on content
    width = max(MIN_BOX_WIDTH, len(sub) + BOX_PADDING)
    box_top = f"{color}┌{'─' * (width - 2)}┐"
    box_bottom = f"{color}└{'─' * (width - 2)}┘"
    
    # Format the content
    content = [
        f"{color}│ {Fore.WHITE}{sub:<{width-4}}{color}│",
        f"{color}│ {Fore.WHITE}IP     : {ip:<{width-15}}{color}│",
        f"{color}│ {Fore.WHITE}HTTP   : {status if status else 'N/A':<{width-15}}{color}│"
    ]
    
    if ssl_info:
        content.append(f"{color}│ {Fore.WHITE}SSL    : Valid{color}│")
        content.append(f"{color}│ {Fore.WHITE}Valid   : {ssl_info['valid_from']} to {ssl_info['valid_until']}{color}│")
        content.append(f"{color}│ {Fore.WHITE}Issuer  : {ssl_info['issuer'].get('CN', 'N/A')}{color}│")
    else:
        content.append(f"{color}│ {Fore.WHITE}SSL    : Not Available{color}│")
    
    # Add HTTP method results
    content.append(f"{color}│ {Fore.WHITE}HTTP Methods:{color}│")
    for method, result in method_results.items():
        if result.get('status'):
            status_str = f"{method}: {result['status']}"
            content.append(f"{color}│ {Fore.WHITE}  {status_str:<{width-6}}{color}│")
            
            # Add headers for this method
            if result.get('headers'):
                for header, value in result['headers'].items():
                    header_str = f"    {header}: {value}"
                    # Wrap long header values
                    wrapped_header = textwrap.wrap(header_str, width=width-6)
                    for line in wrapped_header:
                        content.append(f"{color}│ {Fore.WHITE}{line:<{width-6}}{color}│")
            
            # Add response preview if available
            if result.get('response_preview'):
                content.append(f"{color}│ {Fore.WHITE}    Response Preview:{color}│")
                wrapped_preview = textwrap.wrap(result['response_preview'], width=width-6)
                for line in wrapped_preview:
                    content.append(f"{color}│ {Fore.WHITE}    {line:<{width-6}}{color}│")
        else:
            error_str = f"  {method}: {result.get('error', 'Failed')}"
            content.append(f"{color}│ {Fore.WHITE}{error_str:<{width-6}}{color}│")
    
    if bypass:
        bypass_type = bypass.get('bypass_type', 'unknown')
        if bypass_type == 'header':
            used = ', '.join([f"{k}: {v}" for k, v in bypass.get('headers', {}).items()])
            bypass_info = f"Header Bypass: {used}"
        elif bypass_type == 'path':
            path = bypass.get('path', 'unknown')
            bypass_info = f"Path Bypass: {path}"
        elif bypass_type == 'combination':
            path = bypass.get('path', 'unknown')
            headers = bypass.get('headers', {})
            used = ', '.join([f"{k}: {v}" for k, v in headers.items()])
            bypass_info = f"Combination: {path} + {used}"
        else:
            bypass_info = str(bypass)
        
        # Wrap long bypass strings
        wrapped_bypass = textwrap.wrap(bypass_info, width=width-15)
        for i, line in enumerate(wrapped_bypass):
            prefix = "Bypass : " if i == 0 else "         "
            content.append(f"{color}│ {Fore.WHITE}{prefix}{line:<{width-15}}{color}│")
    
    for k in DISPLAY_HEADERS:
        if k in headers:
            value = headers[k]
            # Wrap long header values
            wrapped_value = textwrap.wrap(value, width=width-15)
            for i, line in enumerate(wrapped_value):
                prefix = f"{k:<8}: " if i == 0 else "         "
                content.append(f"{color}│ {Fore.WHITE}{prefix}{line:<{width-15}}{color}│")
    
    # Add GitHub context information if available
    if github_context:
        content.append(f"{color}│ {Fore.WHITE}GitHub   : {github_context['total_references']} references{color}│")
        content.append(f"{color}│ {Fore.WHITE}Repos    : {github_context['unique_repositories']} repositories{color}│")
        if github_context['file_paths']:
            files_str = f"Files: {len(github_context['file_paths'])}"
            content.append(f"{color}│ {Fore.WHITE}Files    : {files_str:<{width-15}}{color}│")
    
    # Print the box
    print(box_top)
    for line in content:
        print(line)
    print(box_bottom)
    print()
    
    return {
        'subdomain': sub,
        'ip': ip,
        'status': status,
        'headers': headers,
        'verdict': verdict,
        'bypass': bypass,
        'ssl_info': ssl_info,
        'http_methods': method_results,
        'github_context': github_context
    }

def print_subdomain_summary(results):
    # Group subdomains by status
    live = []
    false_positive = []
    ambiguous = []
    
    for result in results:
        if result['verdict'] == 'live':
            live.append(result['subdomain'])
        elif result['verdict'] == 'false_positive':
            false_positive.append(result['subdomain'])
        else:
            ambiguous.append(result['subdomain'])
    
    # Print summary box
    width = MIN_BOX_WIDTH
    print(f"\n{Fore.CYAN}┌{'─' * (width-2)}┐")
    print(f"{Fore.CYAN}│{'Subdomain Scan Summary':^{width-2}}│")
    print(f"{Fore.CYAN}├{'─' * (width-2)}┤")
    
    # Live subdomains
    print(f"{Fore.CYAN}│{Fore.GREEN} Live Subdomains ({len(live)}):{Fore.WHITE}")
    for sub in sorted(live):
        print(f"{Fore.CYAN}│ {Fore.WHITE}{sub:<{width-4}}│")
    
    # False positives
    if false_positive:
        print(f"{Fore.CYAN}├{'─' * (width-2)}┤")
        print(f"{Fore.CYAN}│{Fore.RED} False Positives ({len(false_positive)}):{Fore.WHITE}")
        for sub in sorted(false_positive):
            print(f"{Fore.CYAN}│ {Fore.WHITE}{sub:<{width-4}}│")
    
    # Ambiguous
    if ambiguous:
        print(f"{Fore.CYAN}├{'─' * (width-2)}┤")
        print(f"{Fore.CYAN}│{Fore.YELLOW} Ambiguous ({len(ambiguous)}):{Fore.WHITE}")
        for sub in sorted(ambiguous):
            print(f"{Fore.CYAN}│ {Fore.WHITE}{sub:<{width-4}}│")
    
    print(f"{Fore.CYAN}└{'─' * (width-2)}┘\n")

def save_json_summary(domain, results):
    # Create results directory if it doesn't exist
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)
    
    # Group subdomains by status
    summary = DEFAULT_SUMMARY_STRUCTURE.copy()
    summary["domain"] = domain
    summary["scan_date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary["total_subdomains"] = len(results)
    
    for result in results:
        subdomain_data = {
            "subdomain": result['subdomain'],
            "ip": result['ip'],
            "status": result['status'],
            "headers": result['headers']
        }
        if result.get('bypass'):
            subdomain_data['bypass'] = result['bypass']
        
        # Add GitHub context if available
        if result.get('github_context'):
            subdomain_data['github_context'] = result['github_context']
            
        if result['verdict'] == 'live':
            summary['live'].append(subdomain_data)
        elif result['verdict'] == 'false_positive':
            summary['false_positive'].append(subdomain_data)
        else:
            summary['ambiguous'].append(subdomain_data)
    
    # Add counts
    summary['live_count'] = len(summary['live'])
    summary['false_positive_count'] = len(summary['false_positive'])
    summary['ambiguous_count'] = len(summary['ambiguous'])
    
    # Save to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{domain}_{timestamp}_summary.json"
    filepath = os.path.join(RESULTS_DIR, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=JSON_INDENT)
    
    return filepath

def save_initial_subdomains(domain, subdomains):
    # Create results directory if it doesn't exist
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)
    
    # Create simple summary with just subdomains
    summary = {
        "domain": domain,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_subdomains": len(subdomains),
        "subdomains": sorted(list(subdomains))
    }
    
    # Save to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{domain}_{timestamp}_subdomains.json"
    filepath = os.path.join(RESULTS_DIR, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=JSON_INDENT)
    
    return filepath

def generate_html_report(domain, results):
    """Generate HTML report using the HTML generator module"""
    html_generator = HTMLReportGenerator()
    return html_generator.generate_report(domain, results)

def main(domain):
    # Import session manager and GitHub parser
    from modules.session_manager import SessionManager
    from modules.github_parser import GitHubURLParser
    
    # Display the Gatepeek banner
    display_banner()
    
    print(f"{Fore.CYAN}[+] Starting subdomain reconnaissance for: {domain}")
    print(f"{Fore.CYAN}[+] Using parallel processing with {MAX_WORKERS} workers\n")
    
    # Collect subdomains from all sources
    github_with_context = get_subdomains_github(domain)
    center = get_subdomains_center(domain)
    wayback = get_subdomains_wayback(domain)

    # Combine all subdomains (GitHub subdomains are now dict keys)
    github_subs = set(github_with_context.keys())
    subs = github_subs | center | wayback
    print(f"{Fore.CYAN}[+] Total unique subdomains: {len(subs)}\n")
    
    # Print GitHub context information
    if github_with_context:
        print(f"{Fore.BLUE}[*] GitHub sources found for {len(github_with_context)} subdomains:")
        for subdomain, contexts in github_with_context.items():
            # Parse GitHub context
            github_context = GitHubURLParser.format_github_context(subdomain, contexts)
            if github_context:
                print(f"{Fore.WHITE}  {subdomain}: {github_context['total_references']} references in {github_context['unique_repositories']} repositories")
                for repo_key, repo_info in list(github_context['repositories'].items())[:2]:  # Show first 2 repos
                    print(f"{Fore.WHITE}    - {repo_key}: {repo_info['total_references']} references")
                if len(github_context['repositories']) > 2:
                    print(f"{Fore.WHITE}    ... and {len(github_context['repositories']) - 2} more repositories")
        print()

    # Save initial subdomains immediately
    json_file = save_initial_subdomains(domain, subs)
    print(f"{Fore.GREEN}[+] Initial subdomains saved to: {json_file}\n")

    # Resolve IP addresses in parallel
    resolved_ips = resolve_ips_parallel(subs)
    print(f"\n{Fore.CYAN}[+] Resolved {len(resolved_ips)} IP addresses\n")

    # Use session manager for better performance
    with SessionManager() as session_manager:
        # Check HTTP responses in parallel
        http_results = check_http_parallel(resolved_ips, session_manager)
        
        # Process results and handle 403 bypasses
        results = []
        for subdomain, http_data in http_results.items():
            ip = http_data['ip']
            status = http_data['status']
            headers = http_data['headers']
            body = http_data['body']
            
            # Get GitHub context if available
            github_context = None
            if subdomain in github_with_context:
                github_context = GitHubURLParser.format_github_context(subdomain, github_with_context[subdomain])
            
            # Handle 403 bypass attempts
            if status == 403:
                print(f"{Fore.YELLOW}    [!] 403 detected for {subdomain} — attempting bypass...")
                bcode, bheaders, bused, bbody = bypass_403(subdomain, session_manager)
                if bcode and bcode not in [403, 401] and bcode != status and bbody != body:
                    # Only consider a true bypass if response is different
                    print(f"{Fore.GREEN}    [+] 403 bypass successful: {bcode} (different content)")
                    result = print_result_box(subdomain, ip, bcode, bheaders, bbody, bused, session_manager, github_context)
                    results.append(result)
                    continue
                elif bcode:
                    print(f"{Fore.YELLOW}    [!] 403 bypass returned {bcode} but content unchanged")
                else:
                    print(f"{Fore.RED}    [-] 403 bypass failed")
            
            # Print result box
            result = print_result_box(subdomain, ip, status, headers, body, session_manager=session_manager, github_context=github_context)
            results.append(result)
    
    # Print summary of all found subdomains
    print_subdomain_summary(results)
    
    # Generate HTML report
    html_file = generate_html_report(domain, results)
    print(f"\n{Fore.GREEN}[+] HTML report generated: {html_file}")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    domain = input(f"{Fore.WHITE}Enter target domain (e.g., example.com): ").strip()
    main(domain)
