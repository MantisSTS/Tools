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
    }
    
    if header_name_lower in security_checks:
        return security_checks[header_name_lower](header_value)
    else:
        # For unknown headers, just check if they exist
        return True, []


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


def highlight_text(text, is_secure):
    """Apply color highlighting to text"""
    if is_secure:
        return f"{Colors.GREEN}{text}{Colors.RESET}"
    else:
        return f"{Colors.YELLOW}{text}{Colors.RESET}"


def make_request(url):
    """Make HTTP request and return response"""
    try:
        # Add schema if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        response = requests.get(url, timeout=10, allow_redirects=True)
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
        """
    )
    
    parser.add_argument('url', help='URL to check')
    parser.add_argument('header', help='Header name to check')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed analysis')
    
    args = parser.parse_args()
    
    # Make the request
    response = make_request(args.url)
    if not response:
        sys.exit(1)
    
    # Check the specific header
    header_value = response.headers.get(args.header, None)
    
    if header_value is None:
        is_secure = False
        issues = [f"Header '{args.header}' is not present in the response"]
    else:
        is_secure, issues = check_security_header(args.header, header_value)
    
    # Print header with URL info
    print("=" * 80)
    print(f"{Colors.BOLD}HTTP Header Security Check{Colors.RESET}")
    print(f"URL: {response.url}")
    print(f"Status: {response.status_code}")
    print(f"Checking Header: {Colors.BOLD}{args.header}{Colors.RESET}")
    print("=" * 80)
    
    # If header is secure, show simple success message
    if is_secure:
        print(f"\n{Colors.GREEN}✓ SECURE: {args.header} header is properly configured{Colors.RESET}")
        if args.verbose:
            print(f"   Value: {Colors.GREEN}{header_value}{Colors.RESET}")
    else:
        # Show detailed output for insecure headers
        print(f"\n{Colors.YELLOW}⚠ SECURITY ISSUE DETECTED{Colors.RESET}")
        
        if header_value is None:
            print(f"   Header: {Colors.YELLOW}{args.header}{Colors.RESET}")
            print(f"   Status: {Colors.YELLOW}MISSING{Colors.RESET}")
        else:
            print(f"   Header: {Colors.YELLOW}{args.header}{Colors.RESET}")
            print(f"   Value:  {Colors.YELLOW}{header_value}{Colors.RESET}")
        
        print(f"\n{Colors.YELLOW}Issues found:{Colors.RESET}")
        for issue in issues:
            print(f"   • {issue}")
    
    # Always show all headers with better formatting
    print(f"\n{Colors.BOLD}Response Headers:{Colors.RESET}")
    print("-" * 50)
    
    # Display all headers in the order returned by the server
    for name, value in response.headers.items():
        if name.lower() == args.header.lower():
            # Only highlight the requested header
            if is_secure:
                print(f"  {Colors.GREEN}{name}: {value}{Colors.RESET}")
            else:
                print(f"  {Colors.YELLOW}{name}: {value}{Colors.RESET}")
        else:
            # Show all other headers without highlighting
            print(f"  {name}: {value}")
    
    print("=" * 80)
    
    # Exit with appropriate code
    sys.exit(0 if is_secure else 1)


if __name__ == "__main__":
    main()
