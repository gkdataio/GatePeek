# HTML Report Generator Module
# This module handles all HTML report generation functionality

import os
import html
from datetime import datetime
from modules.arrays import RESULTS_DIR, HTML_STATUS_CLASSES, DISPLAY_HEADERS

class HTMLReportGenerator:
    """HTML Report Generator for subdomain reconnaissance results"""
    
    def __init__(self):
        self.css_styles = self._get_css_styles()
    
    def _get_css_styles(self):
        """Get CSS styles for the HTML report"""
        return """
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
            .banner { text-align: center; margin-bottom: 20px; }
            .banner h1 { font-size: 2.5em; margin: 0; color: #3498db; text-shadow: 2px 2px 4px rgba(0,0,0,0.5); }
            .banner .motto { font-size: 1.2em; margin: 5px 0; color: #ecf0f1; font-style: italic; }
            .banner .creator { font-size: 1em; margin: 5px 0; color: #bdc3c7; }
            .report-info { border-top: 1px solid #34495e; padding-top: 15px; }
            .report-info h2 { margin: 0 0 10px 0; color: #ecf0f1; }
            .subdomain-card { 
                background-color: white;
                border-radius: 5px;
                padding: 15px;
                margin-bottom: 15px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .live { border-left: 4px solid #2ecc71; }
            .false-positive { border-left: 4px solid #e74c3c; }
            .ambiguous { border-left: 4px solid #f1c40f; }
            .details { margin-top: 10px; }
            .label { font-weight: bold; color: #7f8c8d; }
            .value { color: #2c3e50; }
            .bypass { background-color: #f8f9fa; padding: 10px; border-radius: 3px; margin-top: 10px; }
            .ssl-info { background-color: #e8f4f8; padding: 10px; border-radius: 3px; margin-top: 10px; }
            .http-methods { background-color: #f0f0f0; padding: 10px; border-radius: 3px; margin-top: 10px; }
            .method { margin: 10px 0; padding: 10px; background-color: white; border-radius: 3px; }
            .method-name { font-weight: bold; color: #2c3e50; }
            .method-status { color: #2c3e50; }
            .method-error { color: #e74c3c; }
            .method-headers { margin: 5px 0; padding: 5px; background-color: #f8f9fa; border-radius: 3px; }
            .method-response { 
                margin: 5px 0; 
                padding: 10px; 
                background-color: #f8f9fa; 
                border-radius: 3px; 
                font-family: monospace;
                white-space: pre-wrap;
                word-wrap: break-word;
                max-height: 300px;
                overflow-y: auto;
            }
            .method-response pre {
                margin: 0;
                white-space: pre-wrap;
                word-wrap: break-word;
            }
            .github-context { background-color: #f0f8ff; padding: 10px; border-radius: 3px; margin-top: 10px; }
            .repositories { margin-top: 10px; }
            .repository { margin: 10px 0; padding: 10px; background-color: white; border-radius: 3px; }
            .files { margin: 5px 0; padding: 5px; background-color: #f8f9fa; border-radius: 3px; }
            .file { margin: 5px 0; padding: 5px; background-color: white; border-radius: 3px; }
            .file a { color: #007bff; text-decoration: none; }
            .file a:hover { text-decoration: underline; }
            .bypass { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 10px 0; border-radius: 3px; }
            .bypass-details { background-color: #f8f9fa; padding: 10px; border-radius: 3px; margin: 10px 0; }
            .bypass-details strong { color: #495057; }
            .success { color: #28a745; font-weight: bold; }
            .bypass pre { background-color: #e9ecef; padding: 10px; border-radius: 3px; margin: 5px 0; }
            .bypass-statistics { background-color: #fff3cd; border: 1px solid #ffc107; border-radius: 5px; padding: 20px; margin: 20px 0; }
            .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0; }
            .stat-item { background-color: white; padding: 15px; border-radius: 5px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .stat-item h3 { margin: 0 0 10px 0; color: #495057; }
            .stat-item .count { font-size: 24px; font-weight: bold; color: #28a745; margin: 5px 0; }
            .stat-item .percentage { color: #6c757d; margin: 5px 0; }
            .total-bypasses { text-align: center; font-size: 18px; margin-top: 15px; color: #495057; }
            .footer { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-top: 30px; }
            .footer-content { text-align: center; }
            .footer-content p { margin: 5px 0; }
            .footer-content strong { color: #3498db; }
        </style>
        """
    
    def generate_report(self, domain, results):
        """Generate HTML report for the given domain and results"""
        # Create results directory if it doesn't exist
        if not os.path.exists(RESULTS_DIR):
            os.makedirs(RESULTS_DIR)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{domain}_{timestamp}_report.html"
        filepath = os.path.join(RESULTS_DIR, filename)
        
        html_content = self._generate_html_content(domain, results)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath
    
    def _generate_html_content(self, domain, results):
        """Generate the complete HTML content"""
        # Analyze bypass statistics
        bypass_results = [r for r in results if r.get('bypass')]
        bypass_types = {}
        for result in bypass_results:
            bypass_type = result['bypass'].get('bypass_type', 'unknown')
            bypass_types[bypass_type] = bypass_types.get(bypass_type, 0) + 1
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Gatepeek - Subdomain Recon Report - {domain}</title>
            {self.css_styles}
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="banner">
                        <h1>🔍 GATEPEEK</h1>
                        <p class="motto">see beyond the gate</p>
                        <p class="creator">@gkdata</p>
                    </div>
                    <div class="report-info">
                        <h2>Subdomain Reconnaissance Report</h2>
                        <p><strong>Target Domain:</strong> {domain}</p>
                        <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                    </div>
                </div>
        """
        
        # Add bypass statistics if any bypasses occurred
        if bypass_types:
            html_content += self._generate_bypass_statistics(bypass_types)
        
        # Add subdomain cards
        for result in results:
            html_content += self._generate_subdomain_card(result)
        
        # Add footer with Gatepeek branding
        html_content += f"""
            <div class="footer">
                <div class="footer-content">
                    <p>🔍 Generated by <strong>GATEPEEK</strong> - see beyond the gate</p>
                    <p>Created by <strong>@gkdata</strong> | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                </div>
            </div>
            </div>
        </body>
        </html>
        """
        
        return html_content
    
    def _generate_subdomain_card(self, result):
        """Generate HTML for a single subdomain card"""
        status_class = HTML_STATUS_CLASSES.get(result['verdict'], result['verdict'])
        
        card_html = f"""
            <div class="subdomain-card {status_class}">
                <h3>{result['subdomain']}</h3>
                <div class="details">
                    <p><span class="label">IP:</span> <span class="value">{result['ip']}</span></p>
                    <p><span class="label">HTTP Status:</span> <span class="value">{result['status']}</span></p>
        """
        
        # Add SSL information if available
        if result.get('ssl_info'):
            card_html += self._generate_ssl_section(result['ssl_info'])
        
        # Add HTTP methods section
        card_html += self._generate_http_methods_section(result['http_methods'])
        
        # Add bypass information if available
        if result.get('bypass'):
            card_html += self._generate_bypass_section(result['bypass'])
        
        # Add GitHub context if available
        if result.get('github_context'):
            card_html += self._generate_github_context_section(result['github_context'])
        
        # Add display headers
        card_html += self._generate_headers_section(result['headers'])
        
        card_html += """
                </div>
            </div>
        """
        
        return card_html
    
    def _generate_ssl_section(self, ssl_info):
        """Generate SSL information section"""
        return f"""
            <div class="ssl-info">
                <p><span class="label">SSL Certificate:</span></p>
                <p><span class="label">Valid From:</span> <span class="value">{ssl_info['valid_from']}</span></p>
                <p><span class="label">Valid Until:</span> <span class="value">{ssl_info['valid_until']}</span></p>
                <p><span class="label">Issuer:</span> <span class="value">{ssl_info['issuer'].get('CN', 'N/A')}</span></p>
            </div>
        """
    
    def _generate_http_methods_section(self, http_methods):
        """Generate HTTP methods section"""
        methods_html = """
            <div class="http-methods">
                <p><span class="label">HTTP Methods:</span></p>
        """
        
        for method, method_result in http_methods.items():
            methods_html += f"""
                <div class="method">
                    <div class="method-name">{method}</div>
            """
            
            if method_result.get('status'):
                methods_html += f"""
                    <div class="method-status">Status: {method_result['status']}</div>
                """
                
                # Add headers if available
                if method_result.get('headers'):
                    methods_html += self._generate_method_headers(method_result['headers'])
                
                # Add response preview if available
                if method_result.get('response_preview'):
                    methods_html += self._generate_response_preview(method_result['response_preview'])
            else:
                methods_html += f"""
                    <div class="method-error">{html.escape(method_result.get('error', 'Failed'))}</div>
                """
            
            methods_html += """
                </div>
            """
        
        methods_html += """
            </div>
        """
        
        return methods_html
    
    def _generate_method_headers(self, headers):
        """Generate method headers section"""
        headers_html = """
            <div class="method-headers">
                <div class="label">Headers:</div>
        """
        
        for header, value in headers.items():
            headers_html += f"""
                <div><span class="label">{header}:</span> <span class="value">{html.escape(str(value))}</span></div>
            """
        
        headers_html += """
            </div>
        """
        
        return headers_html
    
    def _generate_response_preview(self, response_preview):
        """Generate response preview section"""
        return f"""
            <div class="method-response">
                <div class="label">Response Preview:</div>
                <pre>{html.escape(response_preview)}</pre>
            </div>
        """
    
    def _generate_bypass_section(self, bypass):
        """Generate bypass information section"""
        bypass_type = bypass.get('bypass_type', 'unknown')
        
        # Create detailed bypass information
        bypass_details = []
        
        if bypass_type == 'header':
            headers = bypass.get('headers', {})
            headers_str = ', '.join([f"{k}: {v}" for k, v in headers.items()])
            bypass_info = f"Header Bypass: {headers_str}"
            bypass_details.append(f"<strong>Type:</strong> Header Manipulation")
            bypass_details.append(f"<strong>Headers Used:</strong> {html.escape(headers_str)}")
            
        elif bypass_type == 'path':
            path = bypass.get('path', 'unknown')
            bypass_info = f"Path Bypass: {path}"
            bypass_details.append(f"<strong>Type:</strong> Path Traversal/Manipulation")
            bypass_details.append(f"<strong>Path Used:</strong> {html.escape(path)}")
            
        elif bypass_type == 'combination':
            path = bypass.get('path', 'unknown')
            headers = bypass.get('headers', {})
            headers_str = ', '.join([f"{k}: {v}" for k, v in headers.items()])
            bypass_info = f"Combination Bypass: Path={path}, Headers={headers_str}"
            bypass_details.append(f"<strong>Type:</strong> Combined Approach")
            bypass_details.append(f"<strong>Path Used:</strong> {html.escape(path)}")
            bypass_details.append(f"<strong>Headers Used:</strong> {html.escape(headers_str)}")
            
        else:
            bypass_info = str(bypass)
            bypass_details.append(f"<strong>Type:</strong> Unknown")
        
        # Add bypass success indicator
        bypass_details.append(f"<strong>Status:</strong> <span class='success'>✅ Successful</span>")
        
        details_html = '<br>'.join(bypass_details)
        
        return f"""
            <div class="bypass">
                <p><span class="label">🔓 403 Bypass Successful</span></p>
                <div class="bypass-details">
                    {details_html}
                </div>
                <p><span class="label">Method:</span></p>
                <pre>{html.escape(bypass_info)}</pre>
            </div>
        """
    
    def _generate_headers_section(self, headers):
        """Generate display headers section"""
        headers_html = ""
        for header in DISPLAY_HEADERS:
            if header in headers:
                headers_html += f"""
                    <p><span class="label">{header}:</span> <span class="value">{html.escape(str(headers[header]))}</span></p>
                """
        return headers_html
    
    def _generate_bypass_statistics(self, bypass_types):
        """Generate bypass statistics section"""
        if not bypass_types:
            return ""
        
        stats_html = """
            <div class="bypass-statistics">
                <h2>🔓 403 Bypass Statistics</h2>
                <div class="stats-grid">
        """
        
        total_bypasses = sum(bypass_types.values())
        
        for bypass_type, count in bypass_types.items():
            percentage = (count / total_bypasses) * 100
            stats_html += f"""
                <div class="stat-item">
                    <h3>{bypass_type.title()} Bypass</h3>
                    <p class="count">{count}</p>
                    <p class="percentage">{percentage:.1f}%</p>
                </div>
            """
        
        stats_html += f"""
                </div>
                <p class="total-bypasses">Total Successful Bypasses: <strong>{total_bypasses}</strong></p>
            </div>
        """
        
        return stats_html
    
    def _generate_github_context_section(self, github_context):
        """Generate GitHub context section"""
        context_html = f"""
            <div class="github-context">
                <p><span class="label">GitHub Sources:</span></p>
                <p><span class="label">Total References:</span> <span class="value">{github_context['total_references']}</span></p>
                <p><span class="label">Repositories:</span> <span class="value">{github_context['unique_repositories']}</span></p>
                <p><span class="label">Files:</span> <span class="value">{len(github_context['file_paths'])}</span></p>
        """
        
        # Add repository information
        if github_context.get('repositories'):
            context_html += """
                <div class="repositories">
                    <p><span class="label">Repository Details:</span></p>
            """
            for repo_key, repo_info in github_context['repositories'].items():
                context_html += f"""
                    <div class="repository">
                        <p><span class="label">Repository:</span> <span class="value"><a href="{repo_info['repository_url']}" target="_blank">{repo_key}</a></span></p>
                        <p><span class="label">References:</span> <span class="value">{repo_info['total_references']}</span></p>
                """
                
                # Add file information
                if repo_info.get('files'):
                    context_html += """
                        <div class="files">
                            <p><span class="label">Files:</span></p>
                    """
                    for file_info in repo_info['files'][:5]:  # Show first 5 files
                        context_html += f"""
                            <div class="file">
                                <p><span class="label">File:</span> <span class="value"><a href="{file_info['url']}" target="_blank">{file_info['file_path']}</a></span></p>
                        """
                        if file_info.get('line_number'):
                            context_html += f"""
                                <p><span class="label">Line:</span> <span class="value">{file_info['line_number']}</span></p>
                            """
                        context_html += """
                            </div>
                        """
                    
                    if len(repo_info['files']) > 5:
                        context_html += f"""
                            <p><span class="label">And {len(repo_info['files']) - 5} more files...</span></p>
                        """
                    
                    context_html += """
                        </div>
                    """
                
                context_html += """
                    </div>
                """
            
            context_html += """
                </div>
            """
        
        context_html += """
            </div>
        """
        
        return context_html 