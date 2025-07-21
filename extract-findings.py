#!/usr/bin/env python3

"""
Used to extract evidence out of sslscan and testssl (at least that's what it was made for) output
"""

import sys
import re

def extract_findings(filename, keywords):
    results = []
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    current_host = None
    current_ip = None
    current_port = None
    matched_lines = []

    def flush():
        if current_ip and matched_lines:
            identifier = f"{current_host} ({current_ip}:{current_port})" if current_host else f"{current_ip}:{current_port}"
            print(identifier)
            print("-" * len(identifier))
            for line in matched_lines:
                print(line.strip())
            print()

    for line in lines:
        # Detect new host block: testssl.sh style
        match = re.search(r"-->> ([0-9.]+):([0-9]+) \(([^)]+)\) <<--", line)
        if match:
            flush()
            current_ip, current_port, current_host = match.groups()
            matched_lines = []
            continue

        # Detect new host block: sslscan style
        match = re.search(r"Connected to ([0-9.]+)", line)
        if match:
            flush()
            current_ip = match.group(1)
            current_port = None
            current_host = None
            matched_lines = []
            continue

        match = re.search(r"Testing SSL server (\S+) on port (\d+)", line)
        if match:
            current_host, current_port = match.groups()
            continue

        # Match lines containing any keyword (case-insensitive)
        lower_line = line.lower()
        if any(k.lower() in lower_line for k in keywords):
            matched_lines.append(line.strip())

    flush()  # final block

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: ./extract_findings.py <file> <keyword1> [<keyword2> ...]")
        sys.exit(1)

    extract_findings(sys.argv[1], sys.argv[2:])
