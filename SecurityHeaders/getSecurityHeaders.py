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
import os
from pathlib import Path
from urllib.parse import urlparse
import re
from datetime import datetime
import html
import json


class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[42m\033[30m'  # Green background, black text
    YELLOW = '\033[43m\033[30m'  # Yellow background, black text
    RED = '\033[41m\033[30m'    # Red background, black text
    RESET = '\033[0m'           # Reset color
    BOLD = '\033[1m'


RECOMMENDATIONS_CACHE_FILE = Path('.mozilla_header_recommendations.json')


def load_mozilla_recommendations(update=False):
    """Load (and optionally refresh) Mozilla recommended security headers.

    If update=True or cache missing, fetch key MDN pages (best-effort) and cache
    baseline recommended header values plus timestamp and source URLs.
    """
    if RECOMMENDATIONS_CACHE_FILE.exists() and not update:
        try:
            with open(RECOMMENDATIONS_CACHE_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if 'headers' in data:
                    return data['headers']
        except Exception:
            pass  # fall through to rebuild

    # Baseline recommended values derived from Mozilla Observatory / MDN guidance
    headers = {
        'strict-transport-security': {
            'recommended': 'max-age=31536000; includeSubDomains; preload',
            'source': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
            'notes': 'At least 1 year max-age, includeSubDomains, optionally preload'
        },
        'content-security-policy': {
            'recommended': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; form-action 'self'",
            'source': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
            'notes': 'Tight baseline CSP, adjust for needed sources; avoid unsafe-inline/unsafe-eval'
        },
        'x-frame-options': {
            'recommended': 'DENY',
            'source': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
            'notes': 'DENY prevents any framing; SAMEORIGIN acceptable if needed'
        },
        'x-content-type-options': {
            'recommended': 'nosniff',
            'source': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
            'notes': 'Single valid value is nosniff'
        },
        'referrer-policy': {
            'recommended': 'no-referrer',
            'source': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
            'notes': 'no-referrer maximizes privacy; strict-origin-when-cross-origin common alternative'
        },
        'permissions-policy': {
            'recommended': 'camera=(); microphone=(); geolocation=(); payment=()',
            'source': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
            'notes': 'Explicitly disable powerful features unless required'
        },
        'cross-origin-opener-policy': {
            'recommended': 'same-origin',
            'source': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy',
            'notes': 'same-origin for strong isolation'
        },
        'cross-origin-embedder-policy': {
            'recommended': 'require-corp',
            'source': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy',
            'notes': 'require-corp for security; credentialless acceptable when needed'
        },
        'cross-origin-resource-policy': {
            'recommended': 'same-origin',
            'source': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy',
            'notes': 'same-origin (or same-site) mitigates data exfil via speculative attacks'
        },
        'x-dns-prefetch-control': {
            'recommended': 'off',
            'source': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-DNS-Prefetch-Control',
            'notes': 'Disable to reduce metadata leakage unless performance required'
        },
        'cache-control': {
            'recommended': 'no-store',
            'source': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control',
            'notes': 'no-store for sensitive authenticated responses'
        },
        'set-cookie': {
            'recommended': 'Secure; HttpOnly; SameSite=Strict',
            'source': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie',
            'notes': 'Each cookie should include Secure; HttpOnly; SameSite=Strict (or Lax)'
        },
        'access-control-allow-origin': {
            'recommended': 'SPECIFIC-ORIGIN',
            'source': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin',
            'notes': 'Avoid wildcard * for sensitive APIs; echo explicit origin'
        }
    }

    # Best-effort fetch of pages (content not parsed for values yet – placeholder for future enrichment)
    for key, meta in headers.items():
        if update:
            url = meta['source']
            try:
                resp = requests.get(url, timeout=5)
                if resp.ok:
                    meta['fetched_snippet'] = resp.text[:5000]
            except Exception:
                meta['fetched_snippet'] = 'FETCH_FAILED'

    try:
        with open(RECOMMENDATIONS_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump({'fetched_at': datetime.utcnow().isoformat() + 'Z', 'headers': headers}, f, indent=2)
    except Exception:
        pass
    return headers


def get_all_security_header_names(recommendations):
    """Return the ordered list of headers covered by 'all' alias."""
    order = [
    # Information disclosure meta-check (not a real header but a category)
    'info',
        'strict-transport-security',
        'content-security-policy',
        'x-frame-options',
        'x-content-type-options',
        'referrer-policy',
        'permissions-policy',
        'cross-origin-opener-policy',
        'cross-origin-embedder-policy',
        'cross-origin-resource-policy',
        'x-dns-prefetch-control',
        'cache-control',
        'set-cookie',
        'access-control-allow-origin'
    ]
    # Ensure any new cached items also included
    for k in recommendations.keys():
        if k not in order:
            order.append(k)
    return order


def compare_against_recommendation(header_name, header_value, recommendations):
    """Return a list of deviation issues vs Mozilla baseline if any."""
    issues = []
    if header_value is None:
        return issues
    rec = recommendations.get(header_name.lower())
    if not rec:
        return issues
    expected = rec.get('recommended')
    if not expected:
        return issues
    hv = str(header_value).strip()
    # Special-case logic for certain headers
    lname = header_name.lower()
    if lname == 'strict-transport-security':
        if 'max-age=' in hv.lower():
            m = re.search(r'max-age=(\d+)', hv, re.IGNORECASE)
            if m and int(m.group(1)) < 31536000:
                issues.append('HSTS max-age below 31536000 (1 year) recommended baseline')
        for token in ['includesubdomains']:
            if token not in hv.lower():
                issues.append('HSTS missing includeSubDomains')
        # preload optional; no issue if absent
    elif lname == 'set-cookie':
        lv = hv.lower()
        if 'secure' not in lv:
            issues.append('Cookie missing Secure attribute (Mozilla baseline)')
        if 'httponly' not in lv:
            issues.append('Cookie missing HttpOnly attribute (Mozilla baseline)')
        if 'samesite=' not in lv:
            issues.append('Cookie missing SameSite attribute (Mozilla baseline)')
    elif lname == 'content-security-policy':
        if "'unsafe-inline'" in hv or "'unsafe-eval'" in hv:
            issues.append('CSP contains unsafe-inline/unsafe-eval contrary to baseline')
        if 'default-src' not in hv.lower():
            issues.append('CSP missing default-src directive (baseline expects strict default)')
    else:
        # Straightforward comparison (case-insensitive, ignore ordering/whitespace)
        normalized_expected = ' '.join(expected.lower().split())
        normalized_value = ' '.join(hv.lower().split())
        if normalized_expected != 'specific-origin' and normalized_expected not in normalized_value:
            # For headers with simple exact value baseline
            if lname not in ['cache-control', 'permissions-policy']:
                issues.append(f"Value deviates from Mozilla baseline (expected contains '{expected}')")
    return issues


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


def generate_html_output(response, args, is_secure, issues, header_value, display_header, recommendations):
    """Generate HTML output for the security check"""
    
    # HTML template with embedded CSS (professional restyle)
    html_template = """<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>HTTP Header Security Check - {url}</title>
    <style>
        :root {{
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Fira Sans", "Droid Sans", "Helvetica Neue", Arial, sans-serif;
            --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            --color-bg: #f8fafc;
            --color-surface: #ffffff;
            --color-border: #e2e8f0;
            --color-text: #1e293b;
            --color-muted: #64748b;
            --color-accent: #2563eb;
            --color-accent-hover: #1d4ed8;
            --color-secure-bg: #dcfce7;
            --color-secure-border: #16a34a;
            --color-insecure-bg: #fef3c7;
            --color-insecure-border: #f59e0b;
            --color-critical-bg: #fee2e2;
            --color-critical-border: #dc2626;
            --color-rec-bg: #eff6ff;
            --color-rec-border: #2563eb;
            --radius-sm: 4px;
            --radius-md: 8px;
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.04), 0 1px 3px rgba(0,0,0,0.1);
            --shadow-md: 0 4px 12px rgba(0,0,0,0.08);
            --gradient-accent: linear-gradient(135deg,#2563eb,#4f46e5);
        }}
        @media (prefers-color-scheme: dark) {{
            :root {{
                --color-bg: #0f172a;
                --color-surface: #1e293b;
                --color-border: #334155;
                --color-text: #f1f5f9;
                --color-muted: #94a3b8;
                --color-secure-bg: #064e3b;
                --color-secure-border: #10b981;
                --color-insecure-bg: #78350f;
                --color-insecure-border: #fbbf24;
                --color-critical-bg: #7f1d1d;
                --color-critical-border: #ef4444;
                --color-rec-bg: #1e3a8a;
                --color-rec-border: #3b82f6;
            }}
        }}
        * {{ box-sizing: border-box; }}
        html {{ scroll-behavior: smooth; }}
        body {{
            margin: 0;
            font-family: var(--font-sans);
            background: var(--color-bg);
            color: var(--color-text);
            -webkit-font-smoothing: antialiased;
        }}
        .topbar {{
            background: var(--gradient-accent);
            color: #fff;
            padding: 14px 28px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 600;
            letter-spacing: .5px;
            box-shadow: var(--shadow-sm);
        }}
        .topbar small {{ font-weight: 400; opacity: .85; }}
        .container {{
            max-width: 1180px;
            margin: 32px auto 56px;
            padding: 0 24px 40px;
        }}
        h1 {{ font-size: 1.9rem; margin: 0 0 1rem; line-height: 1.25; }}
        h2 {{ font-size: 1.25rem; margin: 2.5rem 0 1rem; }}
        code, pre {{ font-family: var(--font-mono); font-size: .875rem; }}
        .panel {{
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-md);
            padding: 20px 22px;
            margin-bottom: 28px;
            box-shadow: var(--shadow-sm);
            position: relative;
        }}
        .panel.header-panel {{
            padding-top: 26px;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit,minmax(220px,1fr));
            gap: 14px 32px;
            margin-top: 12px;
        }}
        .meta-item span {{ display: block; font-size: .65rem; text-transform: uppercase; letter-spacing: .08em; font-weight: 600; color: var(--color-muted); margin-bottom: 4px; }}
        .status-block {{
            border-left: 5px solid var(--color-secure-border);
            background: var(--color-secure-bg);
            color: var(--color-text);
            padding: 18px 20px 16px;
            border-radius: var(--radius-md);
            margin: 0 0 24px;
            box-shadow: var(--shadow-sm);
        }}
        .status-block.insecure {{
            border-color: var(--color-insecure-border);
            background: var(--color-insecure-bg);
        }}
        .status-block.critical {{
            border-color: var(--color-critical-border);
            background: var(--color-critical-bg);
        }}
        .status-block h3 {{ margin: 0 0 12px; font-size: 1rem; letter-spacing: .5px; text-transform: uppercase; }}
        .issues-list ul {{ margin: 0; padding-left: 18px; }}
        .issues-list li {{ margin: 4px 0; line-height: 1.4; }}
        .badge {{ display: inline-block; font-size: .625rem; font-weight: 700; letter-spacing: .08em; padding: 4px 8px; border-radius: 999px; background: var(--color-accent); color: #fff; margin-right: 8px; vertical-align: middle; }}
        .badge.secure {{ background: #16a34a; }}
        .badge.insecure {{ background: #f59e0b; }}
        .badge.critical {{ background: #dc2626; }}
        .recommendation {{
            background: var(--color-rec-bg);
            border: 1px solid var(--color-rec-border);
            padding: 14px 16px 12px;
            border-radius: var(--radius-md);
            font-size: .83rem;
            margin-top: 18px;
            line-height: 1.45;
        }}
        .recommendation strong {{ font-size: .75rem; letter-spacing: .07em; text-transform: uppercase; color: var(--color-rec-border); }}
        .recommendation code {{ background: rgba(0,0,0,.06); padding: 2px 5px; border-radius: 4px; font-size: .75rem; }}
        @media (prefers-color-scheme: dark) {{ .recommendation code {{ background: rgba(255,255,255,.12); }} }}
        .request-section, .headers-section {{ margin-top: 42px; }}
        .request-title, .headers-title {{ font-size: 1rem; font-weight: 600; letter-spacing: .04em; text-transform: uppercase; color: var(--color-muted); margin-bottom: 10px; }}
        .request-container, .headers-container {{
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-sm);
            padding: 16px 18px;
            font-family: var(--font-mono);
            font-size: .75rem;
            line-height: 1.4;
            box-shadow: var(--shadow-sm);
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .header-highlighted-inline {{ background: var(--color-insecure-bg); padding: 2px 6px; border-radius: 4px; font-weight: 600; box-decoration-break: clone; }}
        .header-secure-inline {{ background: var(--color-secure-bg); padding: 2px 6px; border-radius: 4px; font-weight: 600; }}
        a {{ color: var(--color-accent); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .actions {{ margin: 28px 0 10px; display: flex; gap: 12px; flex-wrap: wrap; }}
        .btn {{
            background: var(--gradient-accent);
            color: #fff;
            padding: 10px 18px;
            border: none;
            border-radius: var(--radius-sm);
            font-weight: 600;
            letter-spacing: .5px;
            cursor: pointer;
            box-shadow: var(--shadow-sm);
            transition: transform .15s ease, box-shadow .15s ease;
        }}
        .btn:hover {{ transform: translateY(-2px); box-shadow: var(--shadow-md); }}
        .btn:active {{ transform: translateY(0); }}
        .copy-success {{ background: #16a34a; color: #fff; padding: 8px 14px; border-radius: var(--radius-sm); font-size: .7rem; font-weight: 600; letter-spacing: .05em; display: none; align-self: center; }}
        footer {{ margin-top: 60px; padding: 32px 0 12px; font-size: .7rem; text-align: center; color: var(--color-muted); }}
        footer hr {{ border: none; border-top: 1px solid var(--color-border); margin-bottom: 28px; }}
        .timestamp {{ display: block; margin-top: 8px; font-size: .65rem; letter-spacing: .06em; }}
        .visually-hidden {{ position: absolute; width: 1px; height: 1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0 0 0 0); border:0; }}
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
    <div class="topbar">HTTP Header Security Check <small>{timestamp}</small></div>
    <div class="container">
        <div class="panel header-panel">
            <h1>HTTP Header Security Check</h1>
            <div class="meta-grid">
                <div class="meta-item"><span>URL</span>{url}</div>
                <div class="meta-item"><span>Status Code</span>{status}</div>
                <div class="meta-item"><span>Header Checked</span>{header}</div>
            </div>
        </div>

        {status_section}

        <div class="actions">
            <button class="btn" onclick="copyEvidence()" aria-label="Copy formatted evidence">Copy Evidence</button>
            <span id="copy-success" class="copy-success">✓ COPIED</span>
        </div>

        <section class="request-section" aria-labelledby="req-title">
            <h2 id="req-title" class="request-title">Raw HTTP Request</h2>
            <div class="request-container">{raw_request}</div>
        </section>

        <section class="headers-section" aria-labelledby="resp-headers-title">
            <h2 id="resp-headers-title" class="headers-title">Response Headers</h2>
            {headers_content}
        </section>

        <footer>
            <hr>
            Generated by HTTP Header Security Checker <span class="timestamp">Generated {timestamp}</span>
        </footer>
    </div>
</body>
</html>"""

    # Generate status section
    # Mozilla recommendation (if any and not info)
    rec_block = ''
    if args.header.lower() != 'info':
        rec = recommendations.get(args.header.lower())
        if rec:
            rec_value = rec.get('recommended', '') or ''
            rec_notes = rec.get('notes', '') or ''
            rec_source = rec.get('source', '') or ''
            rec_block = "<div class='recommendation'><strong>Mozilla Recommendation:</strong><br>"
            if rec_value:
                rec_block += f"<strong>Value:</strong> <code>{html.escape(rec_value)}</code><br>"
            if rec_notes:
                rec_block += f"<strong>Notes:</strong> {html.escape(rec_notes)}<br>"
            if rec_source:
                rec_block += f"<a href='{html.escape(rec_source)}' target='_blank' rel='noopener noreferrer'>MDN Source</a>"
            rec_block += '</div>'

    if is_secure:
        if args.header.lower() == 'info':
            status_section = '<div class="panel status-block"><h3><span class="badge secure">SECURE</span>No information disclosure headers detected</h3>'
        else:
            status_section = f'<div class="panel status-block"><h3><span class="badge secure">SECURE</span>{html.escape(args.header)} header is properly configured</h3>'
            if args.verbose and header_value:
                status_section += f'<div style="font-family:var(--font-mono);font-size:.75rem;opacity:.85;">Value: <code>{html.escape(str(header_value))}</code></div>'
        status_section += '</div>'
    else:
        block_class = 'status-block insecure'
        badge_class = 'badge insecure'
        title_text = 'SECURITY ISSUE'
        if args.header.lower() == 'info':
            title_text = 'INFORMATION DISCLOSURE'
        status_section = f'<div class="panel {block_class}"><h3><span class="{badge_class}">{title_text}</span>{html.escape(args.header)}</h3>'
        if args.header.lower() != 'info':
            if header_value is None:
                status_section += '<div style="font-family:var(--font-mono);font-size:.75rem;">Status: <code>MISSING</code></div>'
            else:
                status_section += f'<div style="font-family:var(--font-mono);font-size:.75rem;">Value: <code>{html.escape(str(header_value))}</code></div>'
        if issues:
            status_section += '<div class="issues-list"><ul>'
            for issue in issues:
                status_section += f'<li>{html.escape(issue)}</li>'
            status_section += '</ul></div>'
        status_section += '</div>'

    if rec_block:
        status_section += rec_block

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


def make_request(url, follow_redirects=False):
    """Make HTTP request and return response with redirect information"""
    try:
        # Add schema if missing
        original_url = url
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Store the original URL for reference
        if follow_redirects:
            # Capture all redirects
            response = requests.get(url, timeout=10, allow_redirects=True)
            # Get the redirect chain
            redirect_history = response.history
        else:
            # Only get final response
            response = requests.get(url, timeout=10, allow_redirects=True)
            redirect_history = []
        
        # Build the raw HTTP request for the original URL
        parsed_url = urlparse(url)  # Use original URL for request
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
        
        # Add additional information to the response object
        response.raw_request = raw_request
        response.original_url = original_url
        response.redirect_history = redirect_history
        response.follow_redirects = follow_redirects
        
        # Always return the response, even for HTTP error codes (403, 401, etc.)
        # The security analysis should still be performed on error responses
        return response
    except requests.RequestException as e:
        print(f"Error making request to {url}: {e}")
        # Create a lightweight dummy response object so we can surface the error in reports
        class DummyResponse:
            def __init__(self, original_url, error_message):
                self.url = original_url
                self.original_url = original_url
                self.status_code = 0
                self.headers = {}
                self.raw_request = f"GET / HTTP/1.1\r\nHost: {original_url}\r\n\r\n"
                self.redirect_history = []
                self.follow_redirects = follow_redirects
                self.error_message = error_message
        return DummyResponse(url, str(e))


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
    parser.add_argument('--follow-redirects', action='store_true',
                       help='Include all redirect responses in output (default: only final response)')
    parser.add_argument('--update-mozilla-cache', action='store_true',
                       help='Refresh cached Mozilla recommended header values')
    
    args = parser.parse_args()
    
    # Load recommendations (possibly updating cache)
    recommendations = load_mozilla_recommendations(update=args.update_mozilla_cache)

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
        
        # Parse headers from comma-separated string; expand 'all'
        raw_headers = [h.strip() for h in args.headers.split(',') if h.strip()]
        headers = []
        for h in raw_headers:
            if h.lower() == 'all':
                headers.extend(get_all_security_header_names(recommendations))
            else:
                headers.append(h)
        
        if not headers:
            print("Error: No headers specified")
            sys.exit(1)
        
        # Process all combinations
        results = process_batch(urls, headers, args, recommendations)

        # Generate grouped HTML report if requested
        if args.output_html:
            generate_grouped_html_report(results, args, recommendations)
        
    else:
        # Single URL/header mode (existing functionality)
        if not args.url or not args.header:
            print("Error: URL and header are required, or use --urls and --headers for batch processing")
            sys.exit(1)

        if args.header.lower() == 'all':
            header_list = get_all_security_header_names(recommendations)
            results = process_batch([args.url], header_list, args, recommendations)
            if args.output_html:
                generate_grouped_html_report(results, args, recommendations)
        else:
            process_single_check(args.url, args.header, args, recommendations)


def process_batch(urls, headers, args, recommendations):
    """Process multiple URLs and headers, returning results grouped by header and issue type"""
    results = {}
    total_checks = len(urls) * len(headers)
    current_check = 0
    
    print(f"Processing {len(urls)} URLs with {len(headers)} headers ({total_checks} total checks)...")
    
    for header in headers:
        # Initialize header results with missing and insecure categories
        results[header] = {
            'missing': [],
            'insecure': [],
            'secure': [],
            'errors': []  # request/transport errors
        }
        
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
            response = make_request(url, getattr(args, 'follow_redirects', False))
            if getattr(response, 'error_message', None):
                results[header]['errors'].append({
                    'url': url,
                    'original_url': url,
                    'status_code': 0,
                    'header_name': header,
                    'header_value': None,
                    'display_header': header,
                    'is_secure': False,
                    'issues': [f"Request failed: {response.error_message}"],
                    'response': response
                })
                print(f"   • Request error recorded: {response.error_message}")
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
                    issues += compare_against_recommendation(header, header_value, recommendations)
                display_header = header
            
            # Store result - use original URL for consistency
            result = {
                'url': response.url,  # Final URL after redirects
                'original_url': response.original_url,  # Original URL from input
                'status_code': response.status_code,
                'header_name': header,
                'header_value': header_value,
                'display_header': display_header,
                'is_secure': is_secure,
                'issues': issues,
                'response': response
            }
            
            # Categorize result based on whether header is missing vs insecure
            if is_secure:
                results[header]['secure'].append(result)
            elif header_value is None and header.lower() != 'info':
                # Header is missing
                results[header]['missing'].append(result)
            else:
                # Header is present but insecure, or info disclosure
                results[header]['insecure'].append(result)
            
            # Print console output using simplified version
            print("=" * 60)
            print(f"Original URL: {response.original_url}")
            if response.url != response.original_url:
                print(f"Final URL: {response.url}")
                if hasattr(response, 'redirect_history') and response.redirect_history:
                    print(f"Redirects: {len(response.redirect_history)}")
            print(f"Status: {response.status_code}")
            print(f"Header: {display_header}")
            # Mozilla recommendation (console batch)
            if header.lower() != 'info':
                rec = recommendations.get(header.lower()) if recommendations else None
                if rec:
                    print("Mozilla Baseline:")
                    if rec.get('recommended'):
                        print(f"  Expected: {rec['recommended']}")
                    if rec.get('notes'):
                        print(f"  Notes:    {rec['notes']}")
                    if rec.get('source'):
                        print(f"  Source:   {rec['source']}")
            
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


def generate_grouped_html_report(results, args, recommendations):
    """Generate grouped HTML report organized by header type"""
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"security-report-{timestamp}.html"
    
    html_content = generate_grouped_html_content(results, timestamp, recommendations)
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"Grouped HTML report saved to: {filename}")
    except Exception as e:
        print(f"Error saving grouped HTML report: {e}")


def generate_issue_type_section(results, category_type, section_title, css_class, recommendations):
    """Generate a section for a specific issue type (missing or insecure)"""
    section_id = f"{css_class}-headers" if css_class in ["missing", "insecure", "secure"] else css_class
    section_html = f'<div class="issue-type-group" id="{section_id}">'
    section_html += f'<h1 class="issue-type-title {css_class}">{html.escape(section_title)}</h1>'
    
    has_results = False
    
    for header_name, categories in results.items():
        category_results = categories.get(category_type, [])
        if not category_results:
            continue
            
        has_results = True
        section_html += f'<div class="header-group">'
        section_html += f'<h2 class="header-group-title">{html.escape(header_name)}</h2>'
        
        # Add "Copy All Evidence" button for this header/category (omit for secure to reduce clutter if desired)
        clean_header = re.sub(r'[^a-zA-Z0-9]', '', header_name)
        if category_type not in ('secure','errors'):
            section_html += ('<div style="padding: 15px; background-color: #f8f9fa; border-bottom: 1px solid #dee2e6;">'
                              f'<button class="copy-all-button" onclick="copyAllEvidence(\'{html.escape(header_name)}\', \'{category_type}\')">Copy All {html.escape(header_name)} Evidence</button>'
                              f'<span id="copy-all-success-{clean_header}-{category_type}" class="copy-success">✓ All evidence copied!</span>'
                              '</div>')
        
        for i, result in enumerate(category_results):
            section_html += f'<div class="url-result">'
            
            # URL info
            section_html += f'<div class="url-info">'
            section_html += f'<strong>Original URL:</strong> {html.escape(result["original_url"])}<br>'
            if result["url"] != result["original_url"]:
                section_html += f'<strong>Final URL:</strong> {html.escape(result["url"])}<br>'
                if hasattr(result['response'], 'redirect_history') and result['response'].redirect_history:
                    section_html += f'<strong>Redirects:</strong> {len(result["response"].redirect_history)}<br>'
            section_html += f'<strong>Status Code:</strong> {result["status_code"]}<br>'
            section_html += f'</div>'
            
            # Status section
            if category_type == 'errors':
                section_html += f"<div class=\"status-insecure\"><strong>✗ REQUEST ERROR:</strong> {html.escape(result['original_url'])}"
                if result['issues']:
                    section_html += '<div class="issues-list"><strong>Details:</strong><ul>'
                    for issue in result['issues']:
                        section_html += f'<li>{html.escape(issue)}</li>'
                    section_html += '</ul></div>'
            elif category_type == 'missing':
                section_html += f'<div class="status-missing"><strong>⚠ MISSING HEADER:</strong> {html.escape(result["header_name"])}'
            elif category_type == 'insecure':
                if result['header_name'].lower() == 'info':
                    section_html += f'<div class="status-info"><strong>⚠ INFORMATION DISCLOSURE DETECTED</strong>'
                else:
                    section_html += f'<div class="status-insecure"><strong>⚠ INSECURE HEADER:</strong> {html.escape(result["header_name"])}'
                    if result['header_value']:
                        section_html += f'<br><strong>Value:</strong> <code>{html.escape(str(result["header_value"]))}</code>'
            else:  # secure
                if result['header_name'].lower() == 'info':
                    section_html += f'<div class="status-secure"><strong>✓ NO INFORMATION DISCLOSURE</strong>'
                else:
                    section_html += f'<div class="status-secure"><strong>✓ SECURE HEADER:</strong> {html.escape(result["header_name"])}'
                    if result['header_value']:
                        section_html += f'<br><strong>Value:</strong> <code>{html.escape(str(result["header_value"]))}</code>'
            
            if result['issues']:
                section_html += '<div class="issues-list"><strong>Issues found:</strong><ul>'
                for issue in result['issues']:
                    section_html += f'<li>{html.escape(issue)}</li>'
                section_html += '</ul></div>'
            # Evidence block (raw request + response headers)
            try:
                raw_request = result['response'].raw_request
            except Exception:
                raw_request = ''
            info_headers = ['server','x-powered-by','x-aspnet-version','x-aspnetmvc-version','x-generator','x-drupal-cache','x-varnish','via','x-served-by','x-cache','x-cache-hits','x-fastcgi-cache','x-mod-pagespeed','x-pingback','x-runtime','x-request-id','x-correlation-id','x-trace-id']
            target_header_lower = result['header_name'].lower()
            resp_lines = []
            for hname, hval in result['response'].headers.items():
                line = f"{hname}: {hval}"
                highlight = False
                if target_header_lower == 'info':
                    if hname.lower() in info_headers or re.search(r'\\d+\\.\\d+', hval):
                        highlight = True
                elif hname.lower() == target_header_lower:
                    highlight = True
                if highlight:
                    resp_lines.append(f"<span class='marker-yellow'>{html.escape(line)}</span>")
                else:
                    resp_lines.append(html.escape(line))
            section_html += ("<details class='evidence'><summary style='cursor:pointer;font-weight:600;'>Show Evidence</summary>"
                             "<div style='margin-top:10px;'>"
                             "<div style='font-size:.65rem;letter-spacing:.08em;text-transform:uppercase;color:var(--color-muted);margin-top:4px;'>Raw HTTP Request</div>"
                             f"<pre class='url-info' style='white-space:pre-wrap;'>{html.escape(raw_request)}</pre>"
                             "<div style='font-size:.65rem;letter-spacing:.08em;text-transform:uppercase;color:var(--color-muted);margin-top:18px;'>Response Headers</div>"
                             "<pre class='url-info' style='white-space:pre-wrap;'>" + "\n".join(resp_lines) + "</pre>" 
                             "</div></details>")

            # Mozilla recommendation block (skip for info)
            if result['header_name'].lower() != 'info' and category_type not in ('secure','errors'):
                rec = recommendations.get(result['header_name'].lower()) if recommendations else None
                if rec:
                    rec_value = rec.get('recommended', '') or ''
                    rec_notes = rec.get('notes', '') or ''
                    rec_source = rec.get('source', '') or ''
                    section_html += "<div class='recommendation'><strong>Mozilla Recommendation:</strong><br>"
                    if rec_value:
                        section_html += f"<strong>Value:</strong> <code>{html.escape(rec_value)}</code><br>"
                    if rec_notes:
                        section_html += f"<strong>Notes:</strong> {html.escape(rec_notes)}<br>"
                    if rec_source:
                        section_html += f"<a href='{html.escape(rec_source)}' target='_blank' rel='noopener noreferrer'>MDN Source</a>"
                    section_html += '</div>'
            
            section_html += '</div>'  # Close status div
            
            # Copy button for individual evidence (not for secure to reduce noise)
            if category_type not in ('secure','errors'):
                clean_header = re.sub(r'[^a-zA-Z0-9]', '', header_name)
                section_html += f'<button class="copy-button" onclick="copyEvidence({i}, \'{html.escape(header_name)}\', \'{category_type}\')">Copy Evidence</button>'
                section_html += f'<span id="copy-success-{i}-{clean_header}-{category_type}" class="copy-success">✓ Copied!</span>'
            
            section_html += f'</div>'  # Close url-result
        
    section_html += f'</div>'  # Close header-group
    
    if not has_results:
        section_html += f'<div class="empty-category">No {section_title.lower()} found</div>'
    
    section_html += f'</div>'  # Close issue-type-group
    
    return section_html if has_results else ""


def generate_grouped_html_content(results, timestamp, recommendations):
    """Generate the HTML content for grouped report with missing/insecure categories"""
    
    html_template = """<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
    <title>HTTP Header Security Report</title>
    <style>
        :root {{
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Fira Sans", "Droid Sans", "Helvetica Neue", Arial, sans-serif;
            --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            --color-bg: #f8fafc;
            --color-surface: #ffffff;
            --color-border: #e2e8f0;
            --color-text: #1e293b;
            --color-muted: #64748b;
            --color-accent: #2563eb;
            --color-accent-hover: #1d4ed8;
            --color-danger: #dc2626;
            --color-warn: #f59e0b;
            --color-info: #0ea5e9;
            --color-secure: #16a34a;
            --gradient-accent: linear-gradient(135deg,#2563eb,#4f46e5);
            --radius-sm:4px; --radius-md:8px; --radius-lg:14px;
            --shadow-sm:0 1px 2px rgba(0,0,0,.04),0 1px 3px rgba(0,0,0,.08);
            --shadow-md:0 6px 18px -4px rgba(0,0,0,.12);
        }}
        @media (prefers-color-scheme: dark) {{
            :root {{
                --color-bg:#0f172a; --color-surface:#1e293b; --color-border:#334155; --color-text:#f1f5f9; --color-muted:#94a3b8; --color-danger:#ef4444; --color-warn:#fbbf24; --color-info:#38bdf8; --color-secure:#22c55e;
            }}
        }}
        * {{ box-sizing:border-box; }}
        html {{ scroll-behavior:smooth; }}
        body {{ margin:0; font-family:var(--font-sans); background:var(--color-bg); color:var(--color-text); }}
        .app-bar {{ background:var(--gradient-accent); color:#fff; padding:14px 30px; display:flex; gap:24px; align-items:center; flex-wrap:wrap; box-shadow:var(--shadow-sm); position:sticky; top:0; z-index:20; }}
        .app-bar h1 {{ margin:0; font-size:1.15rem; letter-spacing:.5px; }}
        .nav-links a {{ color:#fff; text-decoration:none; font-size:.7rem; font-weight:600; letter-spacing:.08em; opacity:.85; padding:6px 10px; border-radius:var(--radius-sm); transition:background .15s; }}
        .nav-links a:hover {{ background:rgba(255,255,255,.12); opacity:1; }}
        .container {{ max-width:1500px; margin:28px auto 60px; padding:0 30px 40px; }}
        .summary {{ background:var(--color-surface); border:1px solid var(--color-border); padding:26px 30px 18px; border-radius:var(--radius-lg); box-shadow:var(--shadow-sm); position:relative; overflow:hidden; }}
        .summary:before {{ content:""; position:absolute; inset:0; background:radial-gradient(circle at 85% 15%,rgba(79,70,229,.18),transparent 55%); pointer-events:none; }}
        .summary h2 {{ margin:0 0 1.4rem; font-size:1.05rem; letter-spacing:.06em; text-transform:uppercase; font-weight:700; color:var(--color-muted); }}
        .stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:18px 28px; }}
        .stat {{ font-size:.8rem; line-height:1.3; }}
        .stat span {{ display:block; font-size:.6rem; letter-spacing:.09em; font-weight:600; text-transform:uppercase; color:var(--color-muted); margin-bottom:4px; }}
        .issue-type-group {{ margin-top:60px; }}
        .issue-type-title {{ font-size:1.6rem; margin:0 0 18px; display:flex; align-items:center; gap:14px; letter-spacing:.5px; }}
        .issue-type-title .badge {{ font-size:.55rem; background:var(--color-danger); }}
        .issue-type-title.missing .badge {{ background:var(--color-warn); }}
        .header-group {{ border:1px solid var(--color-border); border-radius:var(--radius-md); margin:26px 0 38px; background:var(--color-surface); box-shadow:var(--shadow-sm); overflow:hidden; }}
        .header-group-title {{ margin:0; padding:14px 20px 12px; font-size:1rem; font-weight:600; background:var(--color-accent); color:#fff; letter-spacing:.04em; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px; }}
        .url-result {{ padding:22px 22px 18px; border-top:1px solid var(--color-border); font-size:.8rem; display:grid; gap:14px; }}
        .url-result:first-of-type {{ border-top:none; }}
        .url-info {{ background:rgba(0,0,0,.035); border:1px solid var(--color-border); padding:12px 14px; border-radius:var(--radius-sm); font-family:var(--font-mono); font-size:.68rem; line-height:1.3; }}
        @media (prefers-color-scheme: dark) {{ .url-info {{ background:rgba(255,255,255,.06); }} }}
    .status-missing, .status-insecure, .status-info, .status-secure {{ border:1px solid var(--color-border); border-left:5px solid var(--color-warn); background:var(--color-surface); padding:14px 16px 10px; border-radius:var(--radius-sm); font-size:.75rem; box-shadow:var(--shadow-sm); }}
        .status-insecure {{ border-left-color:var(--color-danger); }}
        .status-info {{ border-left-color:var(--color-info); }}
    .status-secure {{ border-left-color:var(--color-secure); }}
        .issues-list ul {{ margin:10px 0 4px; padding-left:18px; }}
        .issues-list li {{ margin:4px 0; line-height:1.35; }}
        .recommendation {{ background:linear-gradient(135deg,rgba(37,99,235,.08),rgba(37,99,235,.02)); border:1px solid var(--color-accent); padding:12px 14px 10px; border-radius:var(--radius-sm); font-size:.68rem; margin-top:12px; line-height:1.4; }}
        .recommendation strong {{ display:block; font-size:.55rem; letter-spacing:.08em; text-transform:uppercase; color:var(--color-accent); margin-bottom:4px; }}
        .recommendation code {{ background:rgba(0,0,0,.06); padding:2px 5px; border-radius:4px; font-size:.6rem; font-family:var(--font-mono); }}
        @media (prefers-color-scheme: dark) {{ .recommendation code {{ background:rgba(255,255,255,.12); }} }}
        .copy-button, .copy-all-button {{ background:var(--gradient-accent); color:#fff; border:none; padding:9px 16px; border-radius:var(--radius-sm); cursor:pointer; font-size:.62rem; font-weight:600; letter-spacing:.06em; box-shadow:var(--shadow-sm); transition:transform .15s ease, box-shadow .15s ease; }}
        .copy-all-button {{ font-size:.65rem; }}
        .copy-button:hover, .copy-all-button:hover {{ transform:translateY(-2px); box-shadow:var(--shadow-md); }}
        .copy-button:active, .copy-all-button:active {{ transform:translateY(0); }}
        .copy-success {{ background:var(--color-secure); color:#fff; padding:5px 10px; border-radius:var(--radius-sm); font-size:.55rem; font-weight:600; display:none; letter-spacing:.05em; }}
        .empty-category {{ text-align:center; padding:30px 0; font-size:.75rem; color:var(--color-muted); font-style:italic; }}
        footer {{ margin-top:80px; font-size:.6rem; text-align:center; color:var(--color-muted); padding:30px 0 12px; }}
        footer hr {{ border:none; border-top:1px solid var(--color-border); margin-bottom:22px; }}
        .badge {{ display:inline-block; padding:5px 10px 4px; border-radius:999px; font-size:.55rem; font-weight:700; letter-spacing:.08em; background:var(--color-danger); color:#fff; }}
        .missing .badge {{ background:var(--color-warn); }}
        .anchor-link {{ text-decoration:none; color:inherit; position:relative; }}
    .anchor-link:hover:after {{ content:"#"; position:absolute; left:-14px; top:0; color:var(--color-accent); }}
    .marker-yellow { background: var(--color-warn); color:#111; padding:2px 4px; border-radius:4px; }
    .marker-green { background: var(--color-secure); color:#fff; padding:2px 4px; border-radius:4px; }
    details.evidence { margin-top:14px; }
    </style>
    <script>
        function copyEvidence(resultIndex, headerName, categoryType) {{
            const result = window.allResults[headerName][categoryType][resultIndex];
            
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
                    responseHtml += '\\n                    <p><mark class="marker-yellow">' + headerText + '</mark></p>';
                }} else {{
                    responseHtml += '\\n                    <p>' + headerText + '</p>';
                }}
            }}
            
            responseHtml += '\\n                </td>\\n            </tr>\\n        </tbody>\\n    </table>\\n</figure>';
            
            const fullHtml = requestHtml + responseHtml;
            
            // Copy to clipboard
            navigator.clipboard.writeText(fullHtml).then(() => {{
                const successMsg = document.getElementById('copy-success-' + resultIndex + '-' + headerName.replace(/[^a-zA-Z0-9]/g, '') + '-' + categoryType);
                successMsg.style.display = 'inline-block';
                setTimeout(() => {{
                    successMsg.style.display = 'none';
                }}, 2000);
            }}).catch(err => {{
                console.error('Failed to copy: ', err);
                alert('Failed to copy evidence. Please select and copy manually.');
            }});
        }}
        
        function copyAllEvidence(headerName, categoryType) {{
            const results = window.allResults[headerName][categoryType];
            let allHtml = '';
            
            // Add affected hosts list
            allHtml += '<p><strong>Affected Hosts:</strong></p>\\n<ul>\\n';
            for (let i = 0; i < results.length; i++) {{
                const result = results[i];
                allHtml += '<li>' + result.originalUrl + '</li>\\n';
            }}
            allHtml += '</ul>\\n\\n';
            
            for (let i = 0; i < results.length; i++) {{
                const result = results[i];
                
                // Add URL separator with strong tag
                allHtml += '<p><strong>' + result.originalUrl + '</strong></p>\\n';
                
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
                        responseHtml += '\\n                    <p><mark class="marker-yellow">' + headerText + '</mark></p>';
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
                const successMsg = document.getElementById('copy-all-success-' + headerName.replace(/[^a-zA-Z0-9]/g, '') + '-' + categoryType);
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
    <div class="app-bar">
        <h1>HTTP Header Security Report</h1>
        <nav class="nav-links" aria-label="Section Navigation">
            <a href="#missing-headers">Missing</a>
            <a href="#insecure-headers">Insecure</a>
            <a href="#secure-headers">Secure</a>
        </nav>
    </div>
    <div class="container">
        <section class="summary" aria-labelledby="summary-heading">
            <h2 id="summary-heading">Summary</h2>
            <div class="stats-grid">
                <div class="stat"><span>Total URLs</span>{total_urls}</div>
                <div class="stat"><span>Total Headers</span>{total_headers}</div>
                <div class="stat"><span>Total Checks</span>{total_checks}</div>
                <div class="stat"><span>Missing</span>{missing_count}</div>
                <div class="stat"><span>Insecure</span>{insecure_count}</div>
                <div class="stat"><span>Secure</span>{secure_count}</div>
                <div class="stat"><span>Errors</span>{error_count}</div>
                <div class="stat"><span>Generated</span>{timestamp}</div>
            </div>
        </section>
        {content_sections}
        <footer>
            <hr>
            Generated by HTTP Header Security Checker — {timestamp}
        </footer>
    </div>
    
    <script>
        window.allResults = {results_json};
    </script>
</body>
</html>"""

    # Generate content sections organized by issue type
    all_urls = set()
    total_checks = 0
    
    # Count totals and categorize
    missing_count = insecure_count = secure_count = error_count = 0
    for header_name, categories in results.items():
        for category_name, category_results in categories.items():
            if not category_results:
                continue
            for result in category_results:
                all_urls.add(result['url'])
                total_checks += 1
            if category_name == 'missing':
                missing_count += len(category_results)
            elif category_name == 'insecure':
                insecure_count += len(category_results)
            elif category_name == 'secure':
                secure_count += len(category_results)
            elif category_name == 'errors':
                error_count += len(category_results)
    
    # Generate sections for Missing, Insecure, Error and Secure headers
    content_sections = []
    
    # Missing Headers Section
    missing_section = generate_issue_type_section(results, 'missing', 'Missing Headers', 'missing', recommendations)
    if missing_section:
        content_sections.append(missing_section)
    
    # Insecure Headers Section 
    insecure_section = generate_issue_type_section(results, 'insecure', 'Insecure Headers', 'insecure', recommendations)
    if insecure_section:
        content_sections.append(insecure_section)
    
    # Errors Section
    errors_section = generate_issue_type_section(results, 'errors', 'Request Errors', 'errors', recommendations)
    if errors_section:
        content_sections.append(errors_section)

    # Secure Headers Section (optional but provides visibility)
    secure_section = generate_issue_type_section(results, 'secure', 'Secure Headers', 'secure', recommendations)
    if secure_section:
        content_sections.append(secure_section)

    # Prepare JavaScript data
    js_results = {}
    for header_name, categories in results.items():
        js_results[header_name] = {}
        for category_name, category_results in categories.items():
            js_results[header_name][category_name] = []
            for result in category_results:
                js_results[header_name][category_name].append({
                    'url': result['url'],
                    'originalUrl': result['original_url'],
                    'statusCode': result['status_code'],
                    'isSecure': result['is_secure'],
                    'headers': dict(result['response'].headers),
                    'rawRequest': result['response'].raw_request,
                    'redirectCount': len(result['response'].redirect_history) if hasattr(result['response'], 'redirect_history') else 0
                })
    
    return html_template.format(
    total_urls=len(all_urls),
    total_headers=len(results),
    total_checks=total_checks,
    missing_count=missing_count,
    insecure_count=insecure_count,
    secure_count=secure_count,
    error_count=error_count,
        timestamp=timestamp,
        content_sections=''.join(content_sections),
        results_json=json.dumps(js_results)
    )


def process_single_check(url, header, args, recommendations):
    """Process a single URL and header (existing functionality)"""
    
    # Make the request
    response = make_request(url, getattr(args, 'follow_redirects', False))
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
            issues += compare_against_recommendation(header, header_value, recommendations)
        
        display_header = header
    
    # Generate output content
    output_lines = []
    output_lines.append("=" * 80)
    output_lines.append(f"HTTP Header Security Check")
    output_lines.append(f"Original URL: {response.original_url}")
    if response.url != response.original_url:
        output_lines.append(f"Final URL: {response.url}")
        if hasattr(response, 'redirect_history') and response.redirect_history:
            output_lines.append(f"Redirects: {len(response.redirect_history)}")
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
    
    # Add redirect information if --follow-redirects flag was used and redirects occurred
    if getattr(args, 'follow_redirects', False) and hasattr(response, 'redirect_history') and response.redirect_history:
        output_lines.append(f"\nRedirect Chain:")
        output_lines.append("-" * 50)
        for i, redirect_resp in enumerate(response.redirect_history, 1):
            output_lines.append(f"Step {i}: {redirect_resp.status_code} {redirect_resp.url}")
            # Show key headers from redirect responses
            for name, value in redirect_resp.headers.items():
                if name.lower() in ['location', 'set-cookie']:
                    output_lines.append(f"  {name}: {value}")
        output_lines.append(f"Final: {response.status_code} {response.url}")
    
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

    # Mozilla baseline (console single)
    if header.lower() != 'info':
        rec = recommendations.get(header.lower()) if recommendations else None
        if rec:
            output_lines.insert( output_lines.index("=" * 80) + 1, "Mozilla Baseline:")
            insert_pos = output_lines.index("Mozilla Baseline:") + 1
            if rec.get('recommended'):
                output_lines.insert(insert_pos, f"  Expected: {rec['recommended']}")
                insert_pos += 1
            if rec.get('notes'):
                output_lines.insert(insert_pos, f"  Notes:    {rec['notes']}")
                insert_pos += 1
            if rec.get('source'):
                output_lines.insert(insert_pos, f"  Source:   {rec['source']}")
    
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
            html_content = generate_html_output(response, args, is_secure, issues, header_value, display_header, recommendations)
            
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
    main()
