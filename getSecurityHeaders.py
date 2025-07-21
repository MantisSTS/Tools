#!/usr/bin/env python3
"""
HTTP Header Security Checker

This script makes a request to a URL and analyzes specific HTTP headers
for security issues, highlighting them with color codes:
- Green: Secure/Valid header
- Yellow: Insecure/Missing/Problematic header
"""

import sys
import argparse
import requests
from urllib.parse import urlparse
import re
from datetime import datetime
import html


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[42m\033[30m'  # Green background, black text
    YELLOW = '\033[43m\033[30m'  # Yellow background, black text
    RED = '\033[41m\033[30m'    # Red background, black text
    RESET = '\033[0m'           # Reset color
    BOLD = '\033[1m'


def check_security_header(header_name, header_value):
    """
    Check if a security header is properly configured
    Returns tuple: (is_secure, issues_list)
    """
    header_name_lower = header_name.lower()
    
    # Special case for information disclosure check
    if header_name_lower == 'info':
        return check_info_disclosure(header_value)  # header_value will be the full response headers
    
    # Security header validation rules
    security_checks = {
        'strict-transport-security': check_hsts,
        'content-security-policy': check_csp,
        'x-frame-options': check_x_frame_options,
        'x-content-type-options': check_x_content_type_options,
        'referrer-policy': check_referrer_policy,
        'permissions-policy': check_permissions_policy,
        'x-xss-protection': check_x_xss_protection,
        'cache-control': check_cache_control,
        'set-cookie': check_cookie_security,
        'access-control-allow-origin': check_cors_allow_origin,
        'cross-origin-opener-policy': check_coop,
        'cross-origin-embedder-policy': check_coep,
        'cross-origin-resource-policy': check_corp,
        'x-dns-prefetch-control': check_dns_prefetch_control,
        'coop': check_coop,  # Alias for cross-origin-opener-policy
        'coep': check_coep,  # Alias for cross-origin-embedder-policy
        'corp': check_corp,  # Alias for cross-origin-resource-policy
    }
    
    if header_name_lower in security_checks:
        return security_checks[header_name_lower](header_value)
    else:
        # For unknown headers, just check if they exist
        return True, []


def check_info_disclosure(response_headers):
    """Check for information disclosure in HTTP headers"""
    issues = []
    
    # Headers that commonly leak server information
    info_disclosure_headers = {
        'server': 'Server header reveals web server software and version',
        'x-powered-by': 'X-Powered-By header reveals technology stack',
        'x-aspnet-version': 'X-AspNet-Version header reveals .NET version',
        'x-aspnetmvc-version': 'X-AspNetMvc-Version header reveals MVC version',
        'x-generator': 'X-Generator header reveals CMS or framework',
        'x-drupal-cache': 'X-Drupal-Cache header reveals Drupal usage',
        'x-varnish': 'X-Varnish header reveals Varnish cache usage',
        'via': 'Via header may reveal proxy/cache information',
        'x-served-by': 'X-Served-By header reveals server information',
        'x-cache': 'X-Cache header reveals caching infrastructure',
        'x-cache-hits': 'X-Cache-Hits header reveals cache statistics',
        'x-fastcgi-cache': 'X-FastCGI-Cache header reveals FastCGI cache usage',
        'x-mod-pagespeed': 'X-Mod-Pagespeed header reveals PageSpeed module',
        'x-pingback': 'X-Pingback header reveals WordPress pingback endpoint',
        'link': 'Link header may reveal API endpoints or relationships',
        'x-runtime': 'X-Runtime header reveals response processing time',
        'x-request-id': 'X-Request-ID header may reveal internal request tracking',
        'x-correlation-id': 'X-Correlation-ID header may reveal internal tracking',
        'x-trace-id': 'X-Trace-ID header may reveal internal tracing'
    }
    
    found_headers = []
    
    # Check each header in the response
    for header_name, header_value in response_headers.items():
        header_lower = header_name.lower()
        
        if header_lower in info_disclosure_headers:
            found_headers.append(f"{header_name}: {header_value}")
            issues.append(f"{info_disclosure_headers[header_lower]} ({header_name}: {header_value})")
    
    # Additional checks for specific patterns
    for header_name, header_value in response_headers.items():
        # Check for version numbers in any header
        if re.search(r'\d+\.\d+', header_value):
            if header_name.lower() not in info_disclosure_headers:
                issues.append(f"Potential version disclosure in {header_name}: {header_value}")
                found_headers.append(f"{header_name}: {header_value}")
    
    if not issues:
        return True, []
    
    return False, issues


def check_hsts(value):
    """Check HSTS header"""
    issues = []
    if not value:
        return False, ["HSTS header is missing"]
    
    # Check for max-age
    if 'max-age=' not in value.lower():
        issues.append("Missing max-age directive")
    else:
        max_age_match = re.search(r'max-age=(\d+)', value, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # Less than 1 year
                issues.append(f"max-age too short ({max_age}s), should be at least 31536000s (1 year)")
    
    # Check for includeSubDomains
    if 'includesubdomains' not in value.lower():
        issues.append("Missing includeSubDomains directive (recommended)")
    
    return len(issues) == 0, issues


def check_csp(value):
    """Check Content Security Policy"""
    issues = []
    if not value:
        return False, ["CSP header is missing"]
    
    # Check for unsafe directives
    unsafe_patterns = [
        r"'unsafe-inline'",
        r"'unsafe-eval'",
        r"data:",
        r"\*"
    ]
    
    for pattern in unsafe_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            issues.append(f"Contains potentially unsafe directive: {pattern}")
    
    # Check for default-src
    if 'default-src' not in value.lower():
        issues.append("Missing default-src directive (recommended)")
    
    return len(issues) == 0, issues


def check_x_frame_options(value):
    """Check X-Frame-Options header"""
    if not value:
        return False, ["X-Frame-Options header is missing"]
    
    valid_values = ['deny', 'sameorigin']
    if value.lower() not in valid_values:
        return False, [f"Invalid value '{value}', should be DENY or SAMEORIGIN"]
    
    return True, []


def check_x_content_type_options(value):
    """Check X-Content-Type-Options header"""
    if not value:
        return False, ["X-Content-Type-Options header is missing"]
    
    if value.lower() != 'nosniff':
        return False, [f"Invalid value '{value}', should be 'nosniff'"]
    
    return True, []


def check_referrer_policy(value):
    """Check Referrer-Policy header"""
    issues = []
    if not value:
        return False, ["Referrer-Policy header is missing"]
    
    secure_policies = [
        'no-referrer',
        'no-referrer-when-downgrade',
        'same-origin',
        'strict-origin',
        'strict-origin-when-cross-origin'
    ]
    
    if value.lower() not in secure_policies:
        issues.append(f"Policy '{value}' may leak referrer information")
    
    return len(issues) == 0, issues


def check_permissions_policy(value):
    """Check Permissions-Policy header"""
    issues = []
    if not value:
        return False, ["Permissions-Policy header is missing"]
    
    # Common risky permissions that should be restricted
    risky_permissions = [
        'camera', 'microphone', 'geolocation', 'payment',
        'usb', 'magnetometer', 'gyroscope', 'accelerometer'
    ]
    
    # Check if risky permissions are allowed for all origins
    for permission in risky_permissions:
        pattern = rf'{permission}=\*'
        if re.search(pattern, value, re.IGNORECASE):
            issues.append(f"Risky permission '{permission}' is allowed for all origins (*)")
    
    # Check for overly permissive policies
    if re.search(r'=\*', value):
        wildcard_matches = re.findall(r'(\w+)=\*', value, re.IGNORECASE)
        if wildcard_matches:
            issues.append(f"Permissions allowed for all origins: {', '.join(wildcard_matches)}")
    
    return len(issues) == 0, issues


def check_x_xss_protection(value):
    """Check X-XSS-Protection header"""
    if not value:
        return False, ["X-XSS-Protection header is missing"]
    
    # Modern browsers prefer CSP over XSS auditor, X-XSS-Protection should be disabled (0)
    # Any other value (1, 1; mode=block, etc.) can cause issues and should be avoided
    if value.strip() != '0':
        return False, [f"X-XSS-Protection should be '0' to disable browser XSS auditor (current: '{value}'). Modern CSP is preferred."]
    
    return True, []


def check_cache_control(value):
    """Check Cache-Control header for sensitive content"""
    issues = []
    if not value:
        return True, []  # Cache-Control is not always required
    
    # For sensitive content, should have no-store or no-cache
    if 'no-store' not in value.lower() and 'no-cache' not in value.lower():
        if 'private' not in value.lower():
            issues.append("May cache sensitive content (consider no-store, no-cache, or private)")
    
    return len(issues) == 0, issues


def check_cookie_security(value):
    """Check Set-Cookie header security"""
    issues = []
    if not value:
        return True, []  # No cookies is fine
    
    # Check for Secure flag
    if 'secure' not in value.lower():
        issues.append("Missing Secure flag")
    
    # Check for HttpOnly flag
    if 'httponly' not in value.lower():
        issues.append("Missing HttpOnly flag")
    
    # Check for SameSite
    if 'samesite' not in value.lower():
        issues.append("Missing SameSite attribute")
    
    return len(issues) == 0, issues


def check_cors_allow_origin(value):
    """Check Access-Control-Allow-Origin header"""
    issues = []
    if not value:
        return False, ["Access-Control-Allow-Origin header is missing"]
    
    # Check for overly permissive wildcard
    if value == '*':
        issues.append("Wildcard (*) allows all origins, which may be insecure for sensitive applications")
    
    # Check for null origin
    if 'null' in value.lower():
        issues.append("'null' origin should be avoided as it can be exploited")
    
    return len(issues) == 0, issues


def check_coop(value):
    """Check Cross-Origin-Opener-Policy header"""
    if not value:
        return False, ["Cross-Origin-Opener-Policy header is missing"]
    
    secure_values = ['same-origin', 'same-origin-allow-popups']
    if value.lower() not in secure_values:
        return False, [f"Invalid value '{value}', should be 'same-origin' or 'same-origin-allow-popups'"]
    
    return True, []


def check_coep(value):
    """Check Cross-Origin-Embedder-Policy header"""
    if not value:
        return False, ["Cross-Origin-Embedder-Policy header is missing"]
    
    secure_values = ['require-corp', 'credentialless']
    if value.lower() not in secure_values:
        return False, [f"Invalid value '{value}', should be 'require-corp' or 'credentialless'"]
    
    return True, []


def check_corp(value):
    """Check Cross-Origin-Resource-Policy header"""
    if not value:
        return False, ["Cross-Origin-Resource-Policy header is missing"]
    
    valid_values = ['same-site', 'same-origin', 'cross-origin']
    if value.lower() not in valid_values:
        return False, [f"Invalid value '{value}', should be 'same-site', 'same-origin', or 'cross-origin'"]
    
    # Note: 'cross-origin' is less secure but may be necessary for some use cases
    if value.lower() == 'cross-origin':
        return True, ["Consider using 'same-site' or 'same-origin' for better security if possible"]
    
    return True, []


def check_dns_prefetch_control(value):
    """Check X-DNS-Prefetch-Control header"""
    if not value:
        return False, ["X-DNS-Prefetch-Control header is missing"]
    
    # For security-conscious applications, DNS prefetching should be disabled
    if value.lower() != 'off':
        return False, [f"DNS prefetching should be disabled with 'off' (current: '{value}') for better privacy"]
    
    return True, []


def highlight_text(text, is_secure):
    """Apply color highlighting to text"""
    if is_secure:
        return f"{Colors.GREEN}{text}{Colors.RESET}"
    else:
        return f"{Colors.YELLOW}{text}{Colors.RESET}"


def generate_html_output(response, args, is_secure, issues, header_value, display_header):
    """Generate HTML output for the security check"""
    
    # HTML template with embedded CSS
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTTP Header Security Check - {url}</title>
    <style>
        body {{
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #333;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            color: #333;
            font-size: 2.2em;
        }}
        .info-section {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
            border-left: 4px solid #007bff;
        }}
        .status-secure {{
            background-color: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #28a745;
            margin-bottom: 20px;
        }}
        .status-insecure {{
            background-color: #fff3cd;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #ffc107;
            margin-bottom: 20px;
        }}
        .status-info {{
            background-color: #fff3cd;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #ffc107;
            margin-bottom: 20px;
        }}
        .issues-list {{
            margin-top: 15px;
        }}
        .issues-list ul {{
            margin: 0;
            padding-left: 20px;
        }}
        .issues-list li {{
            margin-bottom: 8px;
        }}
        .headers-section {{
            margin-top: 30px;
        }}
        .request-section {{
            margin-top: 30px;
        }}
        .headers-title {{
            font-size: 1.5em;
            font-weight: bold;
            margin-bottom: 15px;
            color: #333;
        }}
        .request-title {{
            font-size: 1.5em;
            font-weight: bold;
            margin-bottom: 15px;
            color: #333;
        }}
        .headers-container {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            border-left: 3px solid #dee2e6;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.4;
            word-break: break-all;
            overflow-wrap: break-word;
        }}
        .request-container {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            border-left: 3px solid #28a745;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.4;
            white-space: pre-wrap;
            word-break: break-all;
            overflow-wrap: break-word;
        }}
        .header-highlighted-inline {{
            background-color: #fff3cd;
            padding: 2px 4px;
            border-radius: 3px;
            font-weight: bold;
        }}
        .header-secure-inline {{
            background-color: #d4edda;
            padding: 2px 4px;
            border-radius: 3px;
            font-weight: bold;
        }}
        .header-name {{
            font-weight: bold;
            color: #0056b3;
        }}
        .footer {{
            margin-top: 40px;
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
            border-top: 1px solid #dee2e6;
            padding-top: 20px;
        }}
        .timestamp {{
            margin-top: 10px;
            font-style: italic;
        }}
        .copy-button {{
            background-color: #007bff;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            margin: 20px 0;
            transition: background-color 0.3s;
        }}
        .copy-button:hover {{
            background-color: #0056b3;
        }}
        .copy-button:active {{
            background-color: #004085;
        }}
        .copy-success {{
            background-color: #28a745;
            color: white;
            padding: 8px 15px;
            border-radius: 4px;
            font-size: 14px;
            margin-left: 10px;
            display: none;
        }}
    </style>
    <script>
        function copyEvidence() {{
            // Generate the formatted HTML evidence
            const rawRequest = `{raw_request}`;
            const responseHeaders = {response_headers_json};
            const checkedHeader = '{checked_header}';
            const isSecure = {is_secure_json};
            const statusCode = {status_code};
            
            // Build request HTML
            let requestHtml = '<p><strong>Request:</strong></p>\\n<figure class="table">\\n    <table>\\n        <tbody>\\n            <tr>\\n                <td>';
            
            const requestLines = rawRequest.trim().split('\\r\\n');
            for (let line of requestLines) {{
                if (line.trim()) {{
                    requestHtml += '\\n                    <p><span style="color:rgb(0,0,0);">' + line + '</span></p>';
                }}
            }}
            
            requestHtml += '\\n                </td>\\n            </tr>\\n        </tbody>\\n    </table>\\n</figure>';
            
            // Build response HTML
            let responseHtml = '\\n<p><strong>Response:</strong></p>\\n<figure class="table">\\n    <table>\\n        <tbody>\\n            <tr>\\n                <td>';
            
            // Add status line
            responseHtml += '\\n                    <p>HTTP/' + statusCode + ' OK</p>';
            
            // Add headers with highlighting
            const infoHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 
                               'x-generator', 'x-drupal-cache', 'x-varnish', 'via', 'x-served-by', 
                               'x-cache', 'x-cache-hits', 'x-fastcgi-cache', 'x-mod-pagespeed', 
                               'x-pingback', 'x-runtime', 'x-request-id', 'x-correlation-id', 'x-trace-id'];
            
            for (let [name, value] of Object.entries(responseHeaders)) {{
                const headerText = name + ': ' + value;
                let shouldHighlight = false;
                
                if (checkedHeader.toLowerCase() === 'info') {{
                    // For info disclosure, highlight problematic headers
                    if (infoHeaders.includes(name.toLowerCase()) || /\\d+\\.\\d+/.test(value)) {{
                        shouldHighlight = true;
                    }}
                }} else if (name.toLowerCase() === checkedHeader.toLowerCase()) {{
                    // Highlight the specific header being checked
                    shouldHighlight = true;
                }}
                
                if (shouldHighlight) {{
                    if (isSecure && checkedHeader.toLowerCase() !== 'info') {{
                        responseHtml += '\\n                    <p><mark class="marker-green">' + headerText + '</mark></p>';
                    }} else {{
                        responseHtml += '\\n                    <p><mark class="marker-yellow">' + headerText + '</mark></p>';
                    }}
                }} else {{
                    responseHtml += '\\n                    <p>' + headerText + '</p>';
                }}
            }}
            
            responseHtml += '\\n                </td>\\n            </tr>\\n        </tbody>\\n    </table>\\n</figure>';
            
            const fullHtml = requestHtml + responseHtml;
            
            // Copy to clipboard
            navigator.clipboard.writeText(fullHtml).then(() => {{
                // Show success message
                const successMsg = document.getElementById('copy-success');
                successMsg.style.display = 'inline-block';
                setTimeout(() => {{
                    successMsg.style.display = 'none';
                }}, 2000);
            }}).catch(err => {{
                console.error('Failed to copy: ', err);
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = fullHtml;
                document.body.appendChild(textArea);
                textArea.select();
                try {{
                    document.execCommand('copy');
                    const successMsg = document.getElementById('copy-success');
                    successMsg.style.display = 'inline-block';
                    setTimeout(() => {{
                        successMsg.style.display = 'none';
                    }}, 2000);
                }} catch (err2) {{
                    alert('Failed to copy evidence. Please select and copy manually.');
                }}
                document.body.removeChild(textArea);
            }});
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>HTTP Header Security Check</h1>
        </div>
        
        <div class="info-section">
            <strong>URL:</strong> {url}<br>
            <strong>Status Code:</strong> {status}<br>
            <strong>Checking Header:</strong> {header}<br>
        </div>
        
        {status_section}
        
        <button class="copy-button" onclick="copyEvidence()">Copy Evidence</button>
        <span id="copy-success" class="copy-success">✓ Evidence copied to clipboard!</span>
        
        <div id="evidence-container">
            <div class="request-section">
                <div class="request-title">Raw HTTP Request</div>
                <div class="request-container">{raw_request}</div>
            </div>
            
            <div class="headers-section">
                <div class="headers-title">Response Headers</div>
                {headers_content}
            </div>
        </div>
        
        <div class="footer">
            Generated by HTTP Header Security Checker
            <div class="timestamp">Report generated on {timestamp}</div>
        </div>
    </div>
</body>
</html>"""

    # Generate status section
    if is_secure:
        if args.header.lower() == 'info':
            status_section = '<div class="status-secure"><strong>✓ SECURE:</strong> No information disclosure headers detected</div>'
        else:
            status_section = f'<div class="status-secure"><strong>✓ SECURE:</strong> {args.header} header is properly configured'
            if args.verbose and header_value:
                status_section += f'<br><strong>Value:</strong> <code>{html.escape(str(header_value))}</code>'
            status_section += '</div>'
    else:
        if args.header.lower() == 'info':
            status_section = '<div class="status-info"><strong>⚠ INFORMATION DISCLOSURE DETECTED</strong>'
        else:
            status_section = '<div class="status-insecure"><strong>⚠ SECURITY ISSUE DETECTED</strong>'
            
            if args.header.lower() != 'info' and header_value is None:
                status_section += f'<br><strong>Header:</strong> {args.header}<br><strong>Status:</strong> MISSING'
            elif args.header.lower() != 'info':
                status_section += f'<br><strong>Header:</strong> {args.header}<br><strong>Value:</strong> <code>{html.escape(str(header_value))}</code>'
        
        if issues:
            status_section += '<div class="issues-list"><strong>Issues found:</strong><ul>'
            for issue in issues:
                status_section += f'<li>{html.escape(issue)}</li>'
            status_section += '</ul></div>'
        
        status_section += '</div>'

    # Generate headers content
    headers_content = '<div class="headers-container">'
    for name, value in response.headers.items():
        header_text = f"{name}: {value}"
        
        if args.header.lower() == 'info':
            # For info disclosure, highlight problematic headers
            header_lower = name.lower()
            info_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 
                           'x-generator', 'x-drupal-cache', 'x-varnish', 'via', 'x-served-by', 
                           'x-cache', 'x-cache-hits', 'x-fastcgi-cache', 'x-mod-pagespeed', 
                           'x-pingback', 'x-runtime', 'x-request-id', 'x-correlation-id', 'x-trace-id']
            
            if header_lower in info_headers or re.search(r'\d+\.\d+', value):
                headers_content += f'<div><span class="header-highlighted-inline">{html.escape(header_text)}</span></div>'
            else:
                headers_content += f'<div>{html.escape(header_text)}</div>'
        elif name.lower() == args.header.lower():
            # Highlight the requested header
            if is_secure:
                headers_content += f'<div><span class="header-secure-inline">{html.escape(header_text)}</span></div>'
            else:
                headers_content += f'<div><span class="header-highlighted-inline">{html.escape(header_text)}</span></div>'
        else:
            headers_content += f'<div>{html.escape(header_text)}</div>'
    
    headers_content += '</div>'

    # Fill in the template
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # Prepare data for JavaScript
    import json
    response_headers_json = json.dumps(dict(response.headers))
    is_secure_json = json.dumps(is_secure)
    
    return html_template.format(
        url=html.escape(response.url),
        status=response.status_code,
        header=html.escape(display_header),
        status_section=status_section,
        raw_request=html.escape(response.raw_request).replace('\r\n', '\\r\\n'),
        headers_content=headers_content,
        timestamp=timestamp,
        response_headers_json=response_headers_json,
        checked_header=html.escape(args.header),
        is_secure_json=is_secure_json,
        status_code=response.status_code
    )


def make_request(url):
    """Make HTTP request and return response"""
    try:
        # Add schema if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        response = requests.get(url, timeout=10, allow_redirects=True)
        
        # Build the raw HTTP request for display purposes
        parsed_url = urlparse(response.url)
        host = parsed_url.netloc
        path = parsed_url.path if parsed_url.path else '/'
        if parsed_url.query:
            path += '?' + parsed_url.query
        
        raw_request = f"GET {path} HTTP/1.1\r\n"
        raw_request += f"Host: {host}\r\n"
        raw_request += f"User-Agent: {response.request.headers.get('User-Agent', 'python-requests/2.31.0')}\r\n"
        raw_request += f"Accept-Encoding: gzip, deflate\r\n"
        raw_request += f"Accept: */*\r\n"
        raw_request += f"Connection: keep-alive\r\n"
        raw_request += f"\r\n"
        
        # Add the raw request to the response object for later use
        response.raw_request = raw_request
        
        return response
    except requests.RequestException as e:
        print(f"Error making request to {url}: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Check HTTP headers for security issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s http://example.com strict-transport-security
  %(prog)s https://google.com permissions-policy
  %(prog)s example.com content-security-policy
  %(prog)s https://site.com info  # Check for information disclosure headers
  %(prog)s https://site.com info --output-html  # Generate HTML report
  %(prog)s https://site.com cross-origin-opener-policy  # Check COOP
  %(prog)s https://site.com coop  # Check COOP (alias)
  %(prog)s https://site.com access-control-allow-origin  # Check CORS
  %(prog)s --urls urls.txt --headers "CSP,X-Frame-Options" --output-html  # Batch process multiple URLs and headers
        """
    )
    
    parser.add_argument('url', nargs='?', help='URL to check (or use --urls for batch processing)')
    parser.add_argument('header', nargs='?', help='Header name to check (or use --headers for batch processing)')
    parser.add_argument('--urls', help='File containing URLs to check (one per line)')
    parser.add_argument('--headers', help='Comma-separated headers to check (e.g., "CSP,X-Frame-Options")')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed analysis')
    parser.add_argument('--output', '-o', action='store_true',
                       help='Save output to file: {URL}-{header_name}-{DATE}.txt')
    parser.add_argument('--output-html', action='store_true',
                       help='Save output as HTML file: {URL}-{header_name}-{DATE}.html')
    
    args = parser.parse_args()
    
    # Determine if we're doing batch processing or single URL/header
    if args.urls or args.headers:
        # Batch processing mode
        if not args.urls or not args.headers:
            print("Error: Both --urls and --headers must be specified for batch processing")
            sys.exit(1)
        
        # Read URLs from file
        try:
            with open(args.urls, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: URLs file '{args.urls}' not found")
            sys.exit(1)
        
        # Parse headers from comma-separated string
        headers = [h.strip() for h in args.headers.split(',') if h.strip()]
        
        if not headers:
            print("Error: No headers specified")
            sys.exit(1)
        
        # Process all combinations
        results = process_batch(urls, headers, args)
        
        # Generate grouped HTML report if requested
        if args.output_html:
            generate_grouped_html_report(results, args)
        
    else:
        # Single URL/header mode (existing functionality)
        if not args.url or not args.header:
            print("Error: URL and header are required, or use --urls and --headers for batch processing")
            sys.exit(1)
        
        process_single_check(args.url, args.header, args)


def process_batch(urls, headers, args):
    """Process multiple URLs and headers, returning results grouped by header"""
    results = {}
    total_checks = len(urls) * len(headers)
    current_check = 0
    
    print(f"Processing {len(urls)} URLs with {len(headers)} headers ({total_checks} total checks)...")
    
    for header in headers:
        results[header] = []
        
        for url in urls:
            current_check += 1
            print(f"[{current_check}/{total_checks}] Checking {url} for {header}")
            
            # Create a fake args object for the single check
            single_args = type('Args', (), {})()
            single_args.url = url
            single_args.header = header
            single_args.verbose = args.verbose if hasattr(args, 'verbose') else False
            single_args.output = False  # Don't generate individual files in batch mode
            single_args.output_html = False  # Don't generate individual HTML files in batch mode
            
            # Reuse the existing single check logic
            response = make_request(url)
            if not response:
                continue
            
            # Check the specific header (reuse existing logic)
            if header.lower() == 'info':
                header_value = response.headers
                is_secure, issues = check_security_header(header, header_value)
                display_header = "Information Disclosure Headers"
            else:
                header_value = response.headers.get(header, None)
                
                if header_value is None:
                    is_secure = False
                    issues = [f"Header '{header}' is not present in the response"]
                else:
                    is_secure, issues = check_security_header(header, header_value)
                
                display_header = header
            
            # Store result
            result = {
                'url': response.url,
                'original_url': url,
                'status_code': response.status_code,
                'header_name': header,
                'header_value': header_value,
                'display_header': display_header,
                'is_secure': is_secure,
                'issues': issues,
                'response': response
            }
            
            results[header].append(result)
            
            # Print console output using simplified version
            print("=" * 60)
            print(f"URL: {response.url}")
            print(f"Status: {response.status_code}")
            print(f"Header: {display_header}")
            
            if is_secure:
                if header.lower() == 'info':
                    print(f"✓ SECURE: No information disclosure headers detected")
                else:
                    print(f"✓ SECURE: {header} header is properly configured")
            else:
                if header.lower() == 'info':
                    print(f"⚠ INFORMATION DISCLOSURE DETECTED")
                else:
                    print(f"⚠ SECURITY ISSUE: {header}")
                
                for issue in issues:
                    print(f"   • {issue}")
            
            print("=" * 60)
            print()
    
    return results


def generate_grouped_html_report(results, args):
    """Generate grouped HTML report organized by header type"""
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"security-report-{timestamp}.html"
    
    html_content = generate_grouped_html_content(results, timestamp)
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"Grouped HTML report saved to: {filename}")
    except Exception as e:
        print(f"Error saving grouped HTML report: {e}")


def generate_grouped_html_content(results, timestamp):
    """Generate the HTML content for grouped report"""
    
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTTP Header Security Report - Grouped by Header</title>
    <style>
        body {{
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #333;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            color: #333;
            font-size: 2.5em;
        }}
        .header-group {{
            margin-bottom: 40px;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            overflow: hidden;
        }}
        .header-group-title {{
            background-color: #007bff;
            color: white;
            padding: 15px 20px;
            margin: 0;
            font-size: 1.8em;
            font-weight: bold;
        }}
        .url-result {{
            border-bottom: 1px solid #dee2e6;
            padding: 20px;
        }}
        .url-result:last-child {{
            border-bottom: none;
        }}
        .url-info {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid #007bff;
        }}
        .status-secure {{
            background-color: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #28a745;
            margin-bottom: 20px;
        }}
        .status-insecure {{
            background-color: #fff3cd;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #ffc107;
            margin-bottom: 20px;
        }}
        .status-info {{
            background-color: #fff3cd;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #ffc107;
            margin-bottom: 20px;
        }}
        .issues-list {{
            margin-top: 15px;
        }}
        .issues-list ul {{
            margin: 0;
            padding-left: 20px;
        }}
        .issues-list li {{
            margin-bottom: 8px;
        }}
        .copy-button {{
            background-color: #28a745;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            margin-bottom: 15px;
        }}
        .copy-button:hover {{
            background-color: #218838;
        }}
        .copy-all-button {{
            background-color: #dc3545;
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            margin: 20px 0;
            font-weight: bold;
        }}
        .copy-all-button:hover {{
            background-color: #c82333;
        }}
        .copy-success {{
            background-color: #17a2b8;
            color: white;
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 11px;
            margin-left: 10px;
            display: none;
        }}
        .summary {{
            background-color: #e9ecef;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .footer {{
            margin-top: 40px;
            text-align: center;
            color: #6c757d;
            font-size: 0.9em;
            border-top: 1px solid #dee2e6;
            padding-top: 20px;
        }}
    </style>
    <script>
        function copyEvidence(resultIndex, headerName) {{
            const result = window.allResults[headerName][resultIndex];
            
            // Build request HTML
            let requestHtml = '<p><strong>Request:</strong></p>\\n<figure class="table">\\n    <table>\\n        <tbody>\\n            <tr>\\n                <td>';
            
            const requestLines = result.rawRequest.trim().split('\\r\\n');
            for (let line of requestLines) {{
                if (line.trim()) {{
                    requestHtml += '\\n                    <p><span style="color:rgb(0,0,0);">' + line + '</span></p>';
                }}
            }}
            
            requestHtml += '\\n                </td>\\n            </tr>\\n        </tbody>\\n    </table>\\n</figure>';
            
            // Build response HTML
            let responseHtml = '\\n<p><strong>Response:</strong></p>\\n<figure class="table">\\n    <table>\\n        <tbody>\\n            <tr>\\n                <td>';
            
            responseHtml += '\\n                    <p>HTTP/' + result.statusCode + ' OK</p>';
            
            // Add headers with highlighting
            const infoHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 
                               'x-generator', 'x-drupal-cache', 'x-varnish', 'via', 'x-served-by', 
                               'x-cache', 'x-cache-hits', 'x-fastcgi-cache', 'x-mod-pagespeed', 
                               'x-pingback', 'x-runtime', 'x-request-id', 'x-correlation-id', 'x-trace-id'];
            
            for (let [name, value] of Object.entries(result.headers)) {{
                const headerText = name + ': ' + value;
                let shouldHighlight = false;
                
                if (headerName.toLowerCase() === 'info') {{
                    if (infoHeaders.includes(name.toLowerCase()) || /\\d+\\.\\d+/.test(value)) {{
                        shouldHighlight = true;
                    }}
                }} else if (name.toLowerCase() === headerName.toLowerCase()) {{
                    shouldHighlight = true;
                }}
                
                if (shouldHighlight) {{
                    if (result.isSecure && headerName.toLowerCase() !== 'info') {{
                        responseHtml += '\\n                    <p><mark class="marker-green">' + headerText + '</mark></p>';
                    }} else {{
                        responseHtml += '\\n                    <p><mark class="marker-yellow">' + headerText + '</mark></p>';
                    }}
                }} else {{
                    responseHtml += '\\n                    <p>' + headerText + '</p>';
                }}
            }}
            
            responseHtml += '\\n                </td>\\n            </tr>\\n        </tbody>\\n    </table>\\n</figure>';
            
            const fullHtml = requestHtml + responseHtml;
            
            // Copy to clipboard
            navigator.clipboard.writeText(fullHtml).then(() => {{
                const successMsg = document.getElementById('copy-success-' + resultIndex + '-' + headerName.replace(/[^a-zA-Z0-9]/g, ''));
                successMsg.style.display = 'inline-block';
                setTimeout(() => {{
                    successMsg.style.display = 'none';
                }}, 2000);
            }}).catch(err => {{
                console.error('Failed to copy: ', err);
                alert('Failed to copy evidence. Please select and copy manually.');
            }});
        }}
        
        function copyAllEvidence(headerName) {{
            const results = window.allResults[headerName];
            let allHtml = '';
            
            for (let i = 0; i < results.length; i++) {{
                const result = results[i];
                
                // Add URL separator
                allHtml += '<h3>' + result.url + '</h3>\\n';
                
                // Build request HTML
                let requestHtml = '<p><strong>Request:</strong></p>\\n<figure class="table">\\n    <table>\\n        <tbody>\\n            <tr>\\n                <td>';
                
                const requestLines = result.rawRequest.trim().split('\\r\\n');
                for (let line of requestLines) {{
                    if (line.trim()) {{
                        requestHtml += '\\n                    <p><span style="color:rgb(0,0,0);">' + line + '</span></p>';
                    }}
                }}
                
                requestHtml += '\\n                </td>\\n            </tr>\\n        </tbody>\\n    </table>\\n</figure>';
                
                // Build response HTML
                let responseHtml = '\\n<p><strong>Response:</strong></p>\\n<figure class="table">\\n    <table>\\n        <tbody>\\n            <tr>\\n                <td>';
                
                responseHtml += '\\n                    <p>HTTP/' + result.statusCode + ' OK</p>';
                
                // Add headers with highlighting
                const infoHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 
                                   'x-generator', 'x-drupal-cache', 'x-varnish', 'via', 'x-served-by', 
                                   'x-cache', 'x-cache-hits', 'x-fastcgi-cache', 'x-mod-pagespeed', 
                                   'x-pingback', 'x-runtime', 'x-request-id', 'x-correlation-id', 'x-trace-id'];
                
                for (let [name, value] of Object.entries(result.headers)) {{
                    const headerText = name + ': ' + value;
                    let shouldHighlight = false;
                    
                    if (headerName.toLowerCase() === 'info') {{
                        if (infoHeaders.includes(name.toLowerCase()) || /\\d+\\.\\d+/.test(value)) {{
                            shouldHighlight = true;
                        }}
                    }} else if (name.toLowerCase() === headerName.toLowerCase()) {{
                        shouldHighlight = true;
                    }}
                    
                    if (shouldHighlight) {{
                        if (result.isSecure && headerName.toLowerCase() !== 'info') {{
                            responseHtml += '\\n                    <p><mark class="marker-green">' + headerText + '</mark></p>';
                        }} else {{
                            responseHtml += '\\n                    <p><mark class="marker-yellow">' + headerText + '</mark></p>';
                        }}
                    }} else {{
                        responseHtml += '\\n                    <p>' + headerText + '</p>';
                    }}
                }}
                
                responseHtml += '\\n                </td>\\n            </tr>\\n        </tbody>\\n    </table>\\n</figure>';
                
                allHtml += requestHtml + responseHtml;
                
                if (i < results.length - 1) {{
                    allHtml += '\\n<hr>\\n';
                }}
            }}
            
            // Copy to clipboard
            navigator.clipboard.writeText(allHtml).then(() => {{
                const successMsg = document.getElementById('copy-all-success-' + headerName.replace(/[^a-zA-Z0-9]/g, ''));
                successMsg.style.display = 'inline-block';
                setTimeout(() => {{
                    successMsg.style.display = 'none';
                }}, 2000);
            }}).catch(err => {{
                console.error('Failed to copy: ', err);
                alert('Failed to copy all evidence. Please select and copy manually.');
            }});
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>HTTP Header Security Report</h1>
            <p>Grouped by Header Type</p>
        </div>
        
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Total URLs tested:</strong> {total_urls}</p>
            <p><strong>Total headers tested:</strong> {total_headers}</p>
            <p><strong>Total checks performed:</strong> {total_checks}</p>
            <p><strong>Report generated:</strong> {timestamp}</p>
        </div>
        
        {header_sections}
        
        <div class="footer">
            Generated by HTTP Header Security Checker
        </div>
    </div>
    
    <script>
        window.allResults = {results_json};
    </script>
</body>
</html>"""

    # Generate header sections
    header_sections = []
    all_urls = set()
    total_checks = 0
    
    for header_name, header_results in results.items():
        if not header_results:
            continue
            
        section_html = f'<div class="header-group">'
        section_html += f'<h2 class="header-group-title">{html.escape(header_name)}</h2>'
        
        # Add "Copy All Evidence" button for this header
        clean_header = re.sub(r'[^a-zA-Z0-9]', '', header_name)
        section_html += f'<div style="padding: 15px; background-color: #f8f9fa; border-bottom: 1px solid #dee2e6;">'
        section_html += f'<button class="copy-all-button" onclick="copyAllEvidence(\'{html.escape(header_name)}\')">Copy All {html.escape(header_name)} Evidence</button>'
        section_html += f'<span id="copy-all-success-{clean_header}" class="copy-success">✓ All evidence copied!</span>'
        section_html += f'</div>'
        
        for i, result in enumerate(header_results):
            all_urls.add(result['url'])
            total_checks += 1
            
            section_html += f'<div class="url-result">'
            
            # URL info
            section_html += f'<div class="url-info">'
            section_html += f'<strong>URL:</strong> {html.escape(result["url"])}<br>'
            section_html += f'<strong>Status Code:</strong> {result["status_code"]}<br>'
            section_html += f'</div>'
            
            # Status section
            if result['is_secure']:
                if result['header_name'].lower() == 'info':
                    section_html += f'<div class="status-secure"><strong>✓ SECURE:</strong> No information disclosure headers detected</div>'
                else:
                    section_html += f'<div class="status-secure"><strong>✓ SECURE:</strong> {html.escape(result["header_name"])} header is properly configured</div>'
            else:
                if result['header_name'].lower() == 'info':
                    section_html += f'<div class="status-info"><strong>⚠ INFORMATION DISCLOSURE DETECTED</strong>'
                else:
                    section_html += f'<div class="status-insecure"><strong>⚠ SECURITY ISSUE DETECTED</strong>'
                    if result['header_value'] is None:
                        section_html += f'<br><strong>Header:</strong> {html.escape(result["header_name"])}<br><strong>Status:</strong> MISSING'
                    else:
                        section_html += f'<br><strong>Header:</strong> {html.escape(result["header_name"])}<br><strong>Value:</strong> <code>{html.escape(str(result["header_value"]))}</code>'
                
                if result['issues']:
                    section_html += '<div class="issues-list"><strong>Issues found:</strong><ul>'
                    for issue in result['issues']:
                        section_html += f'<li>{html.escape(issue)}</li>'
                    section_html += '</ul></div>'
                
                section_html += '</div>'
            
            # Copy button for individual evidence
            clean_header = re.sub(r'[^a-zA-Z0-9]', '', header_name)
            section_html += f'<button class="copy-button" onclick="copyEvidence({i}, \'{html.escape(header_name)}\')">Copy Evidence</button>'
            section_html += f'<span id="copy-success-{i}-{clean_header}" class="copy-success">✓ Copied!</span>'
            
            section_html += f'</div>'  # Close url-result
        
        section_html += f'</div>'  # Close header-group
        header_sections.append(section_html)
    
    # Prepare JavaScript data
    import json
    js_results = {}
    for header_name, header_results in results.items():
        js_results[header_name] = []
        for result in header_results:
            js_results[header_name].append({
                'url': result['url'],
                'statusCode': result['status_code'],
                'isSecure': result['is_secure'],
                'headers': dict(result['response'].headers),
                'rawRequest': result['response'].raw_request
            })
    
    return html_template.format(
        total_urls=len(all_urls),
        total_headers=len(results),
        total_checks=total_checks,
        timestamp=timestamp,
        header_sections=''.join(header_sections),
        results_json=json.dumps(js_results)
    )


def process_single_check(url, header, args):
    """Process a single URL and header (existing functionality)"""
    
    # Make the request
    response = make_request(url)
    if not response:
        sys.exit(1)
    
    # Check the specific header
    if header.lower() == 'info':
        # Special case: check for information disclosure
        header_value = response.headers  # Pass all headers
        is_secure, issues = check_security_header(header, header_value)
        display_header = "Information Disclosure Headers"
    else:
        header_value = response.headers.get(header, None)
        
        if header_value is None:
            is_secure = False
            issues = [f"Header '{header}' is not present in the response"]
        else:
            is_secure, issues = check_security_header(header, header_value)
        
        display_header = header
    
    # Generate output content
    output_lines = []
    output_lines.append("=" * 80)
    output_lines.append(f"HTTP Header Security Check")
    output_lines.append(f"URL: {response.url}")
    output_lines.append(f"Status: {response.status_code}")
    output_lines.append(f"Checking Header: {display_header}")
    output_lines.append("=" * 80)
    
    # Add security analysis
    if is_secure:
        if header.lower() == 'info':
            output_lines.append(f"\n✓ SECURE: No information disclosure headers detected")
        else:
            output_lines.append(f"\n✓ SECURE: {header} header is properly configured")
            if args.verbose and header_value:
                output_lines.append(f"   Value: {header_value}")
    else:
        if header.lower() == 'info':
            output_lines.append(f"\n⚠ INFORMATION DISCLOSURE DETECTED")
        else:
            output_lines.append(f"\n⚠ SECURITY ISSUE DETECTED")
        
        if header.lower() != 'info' and header_value is None:
            output_lines.append(f"   Header: {header}")
            output_lines.append(f"   Status: MISSING")
        elif header.lower() != 'info':
            output_lines.append(f"   Header: {header}")
            output_lines.append(f"   Value:  {header_value}")
        
        output_lines.append(f"\nIssues found:")
        for issue in issues:
            output_lines.append(f"   • {issue}")
    
    # Add raw HTTP request
    output_lines.append(f"\nRaw HTTP Request:")
    output_lines.append("-" * 50)
    output_lines.append(response.raw_request.rstrip())
    
    # Add all headers
    output_lines.append(f"\nResponse Headers:")
    output_lines.append("-" * 50)
    
    for name, value in response.headers.items():
        if header.lower() == 'info':
            # For info disclosure, highlight any problematic headers
            header_lower = name.lower()
            info_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 
                           'x-generator', 'x-drupal-cache', 'x-varnish', 'via', 'x-served-by', 
                           'x-cache', 'x-cache-hits', 'x-fastcgi-cache', 'x-mod-pagespeed', 
                           'x-pingback', 'x-runtime', 'x-request-id', 'x-correlation-id', 'x-trace-id']
            
            if header_lower in info_headers or re.search(r'\d+\.\d+', value):
                output_lines.append(f"  {highlight_text(f'{name}: {value}', False)}")
            else:
                output_lines.append(f"  {name}: {value}")
        elif name.lower() == header.lower():
            # Highlight the requested header
            output_lines.append(f"  {highlight_text(f'{name}: {value}', is_secure)}")
        else:
            output_lines.append(f"  {name}: {value}")
    
    output_lines.append("=" * 80)
    
    # Print console output
    print('\n'.join(output_lines))
    
    # Save to file if requested
    if args.output:
        # Create filename
        clean_url = response.url.replace('https://', '').replace('http://', '')
        clean_url = re.sub(r'[^\w\-_.]', '_', clean_url)
        clean_header = re.sub(r'[^\w\-_.]', '_', header)
        date_str = datetime.now().strftime('%Y-%m-%d')
        filename = f"{clean_url}-{clean_header}-{date_str}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write('\n'.join(output_lines))
            print(f"Output saved to: {filename}")
        except Exception as e:
            print(f"Error saving file: {e}")
    
    # Generate HTML output if requested
    if args.output_html:
        try:
            html_content = generate_html_output(response, args, is_secure, issues, header_value, display_header)
            
            # Create filename
            clean_url = response.url.replace('https://', '').replace('http://', '')
            clean_url = re.sub(r'[^\w\-_.]', '_', clean_url)
            clean_header = re.sub(r'[^\w\-_.]', '_', header)
            date_str = datetime.now().strftime('%Y-%m-%d')
            html_filename = f"{clean_url}-{clean_header}-{date_str}.html"
            
            with open(html_filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"HTML output saved to: {html_filename}")
        except Exception as e:
            print(f"Error saving HTML file: {e}")


if __name__ == "__main__":
    import sys
    import argparse
    import requests
    import re
    import html
    import json
    
    main()
