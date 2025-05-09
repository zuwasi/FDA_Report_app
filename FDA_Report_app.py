﻿#!/usr/bin/env python3
# FDA Parasoft Report Viewer – violations and suppressions
# ---------------------------------------------------------
# Requirements (>= Python 3.8):
#   pip install lxml matplotlib pillow beautifulsoup4 requests
# ---------------------------------------------------------
# Parses Parasoft C/C++test HTML or XML reports,
# separates real violations from suppressed items, and produces an
# FDA-style HTML report with progress charts.

import os
import shutil
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox, ttk
from datetime import datetime
import webbrowser
import json
import re
import subprocess

# Try to import requests, but make it optional
try:
    import requests
    import base64
    GITHUB_AVAILABLE = True
except ImportError:
    GITHUB_AVAILABLE = False

import matplotlib.pyplot as plt
from bs4 import BeautifulSoup
from lxml import etree

# Constants & helpers
SEVERITY_LABELS = ["Lowest", "Low", "Medium", "High", "Highest"]
SEV_KEYWORDS = {"lowest": 0, "low": 1, "medium": 2, "high": 3, "highest": 4}


def _detect_severity(text: str) -> int:
    """Determine severity level (0-4) from text."""
    ft = text.lower()
    
    # Look for explicit severity indicators in rule IDs
    if "_2_" in ft or "_3_" in ft:  # Usually high severity rules
        return 3  # High
    if "_8_" in ft or "_11_" in ft:  # Usually medium severity rules
        return 2  # Medium
    if "_21_" in ft:  # Lower severity rules
        return 1  # Low
        
    # Check for severity keywords
    for key, idx in SEV_KEYWORDS.items():
        if key in ft:
            return idx
            
    # If rule has strncpy, memcpy, etc. - usually higher severity
    if any(func in ft for func in ['strcpy', 'memcpy', 'malloc', 'free', 'sizeof']):
        return 3  # High
        
    # If rule mentions unused, declaration, etc. - usually lower severity
    if any(word in ft for word in ['unused', 'declaration', 'identifier']):
        return 1  # Low
        
    return 2  # Medium fallback


def parse_suppression_file(path):
    """Parse a Parasoft .suppress file to extract suppression details.
    
    Args:
        path: Path to the .suppress file
        
    Returns:
        List of suppression dictionaries containing details about each suppression
    """
    suppressions = []
    current_suppression = None
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Start of a new suppression block
                if line == 'suppression-begin':
                    current_suppression = {}
                    continue
                
                # End of suppression block - add to list
                if line == 'suppression-end' and current_suppression:
                    suppressions.append(current_suppression)
                    current_suppression = None
                    continue
                
                # Parse suppression details
                if current_suppression is not None and ':' in line:
                    key, value = line.split(':', 1)
                    current_suppression[key.strip()] = value.strip()
    
    except Exception as e:
        print(f"Error parsing suppression file: {e}")
        import traceback
        traceback.print_exc()
    
    # Process suppressions to extract severity information
    for supp in suppressions:
        # Default severity (medium)
        supp['severity'] = 2
        
        # Try to determine severity from rule ID
        rule_id = supp.get('rule-id', '')
        if '_2_' in rule_id or '_3_' in rule_id:
            supp['severity'] = 3  # High
        elif '_8_' in rule_id or '_11_' in rule_id:
            supp['severity'] = 2  # Medium
        elif '_21_' in rule_id:
            supp['severity'] = 1  # Low
        
        # Alternatively, try to determine from message
        message = supp.get('message', '').lower()
        if any(word in message for word in ['critical', 'highest', 'severe']):
            supp['severity'] = 4  # Highest
        elif any(word in message for word in ['high', 'important']):
            supp['severity'] = 3  # High
        elif any(word in message for word in ['low', 'minor']):
            supp['severity'] = 1  # Low
        elif any(word in message for word in ['lowest', 'trivial']):
            supp['severity'] = 0  # Lowest
    
    return suppressions


# Code Line Counter
def count_lines_in_file(file_path):
    """Count number of code lines in a file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Remove comments
            # Remove C-style comments (/* ... */)
            content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
            # Remove C++-style comments (// ...)
            content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
            
            # Count non-empty lines
            lines = [line.strip() for line in content.split('\n')]
            return len([line for line in lines if line])
    except Exception as e:
        print(f"Error counting lines in {file_path}: {e}")
        return 0

def is_source_file(file_path):
    """Check if a file is a C/C++ source file."""
    extensions = ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx']
    return any(file_path.lower().endswith(ext) for ext in extensions)

def count_lines_in_directory(dir_path):
    """Count lines of code in C/C++ files in a directory."""
    total_lines = 0
    source_files = 0
    
    for root, _, files in os.walk(dir_path):
        for file in files:
            file_path = os.path.join(root, file)
            if is_source_file(file_path):
                lines = count_lines_in_file(file_path)
                total_lines += lines
                source_files += 1
    
    return {
        'total_lines': total_lines,
        'source_files': source_files
    }

def try_clone_github_repo(repo_url, temp_dir):
    """Try to clone a GitHub repository for line counting."""
    try:
        # Check if git is available
        subprocess.run(['git', '--version'], check=True, capture_output=True)
        
        # Clone the repository
        subprocess.run(
            ['git', 'clone', '--depth', '1', repo_url, temp_dir], 
            check=True, 
            capture_output=True
        )
        
        return True
    except Exception as e:
        print(f"Error cloning repository: {e}")
        return False

def try_fetch_github_api(repo_url):
    """Try to fetch repository information from GitHub API."""
    if not GITHUB_AVAILABLE:
        return None
        
    try:
        # Extract owner and repo name from URL
        # Supports formats like:
        # https://github.com/owner/repo
        # git@github.com:owner/repo.git
        match = re.search(r'github\.com[/:]([\w-]+)/([\w-]+)', repo_url)
        if not match:
            return None
            
        owner = match.group(1)
        repo = match.group(2)
        if repo.endswith('.git'):
            repo = repo[:-4]
        
        # GitHub API URL
        api_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/main?recursive=1"
        
        # Make request
        response = requests.get(api_url)
        if response.status_code != 200:
            # Try with 'master' branch if 'main' fails
            api_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/master?recursive=1"
            response = requests.get(api_url)
            if response.status_code != 200:
                return None
        
        data = response.json()
        if 'tree' not in data:
            return None
            
        # Get all C/C++ source files
        source_files = []
        for item in data['tree']:
            if item['type'] == 'blob' and is_source_file(item['path']):
                source_files.append({
                    'path': item['path'],
                    'url': item['url']
                })
        
        # Count lines in each file
        total_lines = 0
        processed_files = 0
        
        for file_info in source_files[:100]:  # Limit to 100 files to avoid API rate limits
            try:
                file_url = file_info['url']
                file_response = requests.get(file_url)
                if file_response.status_code == 200:
                    file_data = file_response.json()
                    if 'content' in file_data and file_data.get('encoding') == 'base64':
                        content = base64.b64decode(file_data['content']).decode('utf-8', errors='ignore')
                        
                        # Remove comments
                        # Remove C-style comments (/* ... */)
                        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
                        # Remove C++-style comments (// ...)
                        content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
                        
                        # Count non-empty lines
                        lines = [line.strip() for line in content.split('\n')]
                        line_count = len([line for line in lines if line])
                        total_lines += line_count
                        processed_files += 1
            except Exception as e:
                print(f"Error processing file {file_info['path']}: {e}")
        
        return {
            'total_lines': total_lines,
            'source_files': processed_files,
            'total_source_files': len(source_files)
        }
    except Exception as e:
        print(f"Error using GitHub API: {e}")
        return None

def get_repository_code_info():
    """Get information about code in a repository (local or remote)."""
    repo_info = {
        'total_lines': 0,
        'source_files': 0,
        'repo_path': "",
        'is_github': False
    }
    
    try:
        # Ask if user wants to use GitHub repository
        use_github = messagebox.askyesno(
            "Repository Selection",
            "Do you want to use a GitHub repository?\nSelect 'Yes' for GitHub, 'No' for local directory."
        )
        
        if use_github:
            if not GITHUB_AVAILABLE:
                messagebox.showwarning(
                    "GitHub Unavailable",
                    "GitHub repository analysis requires the 'requests' module, which is not installed.\n\n"
                    "Please install it with: pip install requests\n\n"
                    "Proceeding with local directory selection."
                )
            else:
                # Get GitHub repository URL
                repo_url = simpledialog.askstring(
                    "GitHub Repository",
                    "Enter GitHub repository URL:",
                    initialvalue="https://github.com/username/repo"
                )
                
                if not repo_url:
                    return repo_info
                    
                repo_info['repo_path'] = repo_url
                repo_info['is_github'] = True
                
                # Try GitHub API first
                api_results = try_fetch_github_api(repo_url)
                if api_results:
                    repo_info.update(api_results)
                    if 'total_source_files' in api_results:
                        repo_info['note'] = f"Analyzed {api_results['source_files']} of {api_results['total_source_files']} source files due to API limitations"
                    return repo_info
                
                # If API fails, try cloning
                import tempfile
                temp_dir = tempfile.mkdtemp()
                
                success = try_clone_github_repo(repo_url, temp_dir)
                if success:
                    results = count_lines_in_directory(temp_dir)
                    repo_info.update(results)
                    
                    # Clean up temp directory
                    import shutil
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    
                    return repo_info
                
                # If both methods fail
                messagebox.showwarning(
                    "Repository Access Failed",
                    "Could not access GitHub repository. Please select a local directory instead."
                )
        
        # Use local directory
        dir_path = filedialog.askdirectory(title="Select source code directory")
        if dir_path:
            repo_info['repo_path'] = dir_path
            results = count_lines_in_directory(dir_path)
            repo_info.update(results)
        
        return repo_info
        
    except Exception as e:
        print(f"Error in repository code analysis: {e}")
        import traceback
        traceback.print_exc()
        return repo_info


# Parsers
def parse_html_report(path):
    """Parse a Parasoft HTML report file."""
    vc = [0]*5  # Violation counts by severity
    vd = {i: [] for i in range(5)}  # Violation details by severity
    
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read()
            
        soup = BeautifulSoup(content, "html.parser")
        
        # Find all table rows
        rows = soup.find_all("tr")
        
        current_file = ""
        
        for i, row in enumerate(rows):
            # Get all cells in the row
            cells = row.find_all("td")
            if not cells:
                continue
                
            # Get text from the first cell
            first_cell_text = cells[0].get_text(strip=True)
            
            # Check if this is a file path row
            if first_cell_text.startswith('/') and len(cells) > 1 and not first_cell_text.startswith('//'): 
                current_file = first_cell_text
                continue
                
            # Check if this is a violation row with line number
            line_match = None
            for match in first_cell_text.split(' ', 1):
                if match.endswith(':'):
                    line_match = match.rstrip(':')
                    break
            
            if not line_match or not line_match.isdigit():
                # This might be a file header or other row
                if "Total Tasks" in first_cell_text:
                    # This is a file header with task count
                    file_name = first_cell_text.split("Total")[0].strip()
                    current_file = file_name
                continue
                
            # Extract line number, message, and rule
            ln = int(line_match)
            
            # Extract message - after the line number
            msg = first_cell_text.split(':', 1)[1].strip() if ':' in first_cell_text else first_cell_text
            
            # Extract rule ID from the last cell
            rule = cells[-1].get_text(strip=True) if len(cells) > 1 else ""
            
            # If no rule found or not a proper rule ID, look for it in other cells
            if not rule or 'RULE' not in rule:
                for cell in cells:
                    text = cell.get_text(strip=True)
                    if 'RULE' in text or 'MISRAC' in text:
                        rule = text
                        break
            
            # Determine severity
            sev = 2  # Default to medium
            for key, idx in SEV_KEYWORDS.items():
                if key in msg.lower() or key in rule.lower():
                    sev = idx
                    break
            
            # We only care about violations now, not suppressions from the HTML report
            # Store in violation data structure with file context
            formatted_msg = f"{current_file}: {msg}"
            vc[sev] += 1
            vd[sev].append((ln, formatted_msg, rule))
        
    except Exception as e:
        print(f"Error parsing HTML: {e}")
        import traceback
        traceback.print_exc()
    
    # Return violations only - suppressions will be handled by the .suppress file
    return vc, vd


def parse_xml_report(path):
    """Parse a Parasoft XML report file."""
    vc = [0]*5  # Violation counts by severity
    vd = {i: [] for i in range(5)}  # Violation details by severity
    rules_list = []  # List of all active rules
    tool_info = {}  # Tool information
    
    try:
        tree = etree.parse(path)
        root = tree.getroot()
        
        # Extract tool information
        tool_info["name"] = root.get("toolName", "")
        tool_info["version"] = root.get("toolVer", "")
        tool_info["date"] = root.get("date", "")
        
        # Extract test configuration name (rules standard)
        test_config = root.find(".//TestConfig")
        if test_config is not None:
            tool_info["rules_standard"] = test_config.get("name", "")
        
        # Process all StdViol elements (standard violations)
        for violation in root.xpath("//StdViol"):
            try:
                # Extract data from violation
                severity_str = violation.get("sev", "2")
                try:
                    severity = int(severity_str)
                    # Make sure severity is in valid range [0-4]
                    severity = max(0, min(severity, 4))
                except ValueError:
                    severity = 2  # Default to medium
                
                line_num = violation.get("ln", "0")
                message = violation.get("msg", "")
                rule = violation.get("rule", "")
                file_path = violation.get("locFile", "")
                
                # If file path starts with '/', remove leading slash
                if file_path and file_path.startswith('/'):
                    file_path = file_path[1:]
                
                # Ignore suppression information from XML - we'll use the .suppress file
                # We only count this as a violation
                formatted_msg = f"{file_path}: {message}" if file_path else message
                vc[severity] += 1
                vd[severity].append((line_num, formatted_msg, rule))
            except Exception as e:
                print(f"Error processing violation: {e}")
                continue
                
        # Extract list of active rules
        for rule in root.xpath("//Rule"):
            try:
                rule_id = rule.get("id", "")
                desc = rule.get("desc", "")
                category = rule.get("cat", "")
                
                sev_str = rule.get("sev", "2")
                try:
                    severity = int(sev_str)
                    severity = max(0, min(severity, 4))
                except ValueError:
                    severity = 2
                
                if rule_id:
                    rules_list.append({
                        "id": rule_id,
                        "description": desc,
                        "category": category,
                        "severity": severity
                    })
            except Exception as e:
                print(f"Error processing rule: {e}")
                continue
                
    except Exception as e:
        print(f"Error parsing XML report: {e}")
        import traceback
        traceback.print_exc()
    
    # Return violations only - suppressions will be handled by the .suppress file
    return vc, vd, rules_list, tool_info


def load(path):
    """Load report from file based on extension."""
    print(f"Loading report: {path}")
    
    try:
        if path.lower().endswith(".xml"):
            print(f"Treating as XML report: {path}")
            vc, vd, rules_list, tool_info = parse_xml_report(path)
            return vc, vd, rules_list, tool_info
        else:
            print(f"Treating as HTML report: {path}")
            vc, vd = parse_html_report(path)
            return vc, vd, [], {}
    except Exception as e:
        print(f"Critical error in load function: {e}")
        import traceback
        traceback.print_exc()
        # Return empty data with the correct structure
        return [0]*5, {i: [] for i in range(5)}, [], {}


# Report generation
def create_historical_chart(current, previous_data, out_png):
    """Create a bar chart showing historical progress of violations with trendlines."""
    import numpy as np
    import matplotlib.pyplot as plt

    # Prepare data
    data_points = [counts for _, counts in previous_data] + [current]
    labels = [date for date, _ in previous_data] + ['Current']
    x = np.arange(len(labels))
    width = 0.15

    fig, ax = plt.subplots(figsize=(12, 6))

    for i in range(5):
        # Data for severity level i
        y = [point[i] for point in data_points]
        offset = (i - 2) * width

        # Plot bars
        bars = ax.bar(x + offset, y, width, label=SEVERITY_LABELS[i])

        # Plot trendline
        z = np.polyfit(x, y, 1)
        p = np.poly1d(z)
        ax.plot(x + offset, p(x), linestyle='--', linewidth=1.5)

        # Data labels
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, height + 0.5, str(height),
                        ha='center', va='bottom', fontsize=8)

    ax.set_xlabel('Analysis Date')
    ax.set_ylabel('Number of Violations')
    ax.set_title('Historical Progress of Violations by Severity (with Trendlines)')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right')
    ax.legend()

    plt.tight_layout()
    plt.savefig(out_png)
    plt.close()


def generate_html(user, vc, pc, vd, png, logo, out_html, sc, sd, rules_list=[], repo_info=None):
    """Generate HTML report with violations and suppressions.
    
    Args:
        user: Dictionary of user-provided device information
        vc: List of violation counts by severity
        pc: Previous violation counts (not used in current implementation)
        vd: Dictionary of violation details by severity
        png: Path to the chart image
        logo: Path to logo image
        out_html: Output HTML file path
        sc: List of suppression counts by severity
        sd: Dictionary of suppression details by severity
        rules_list: List of rule dictionaries
        repo_info: Repository code information (optional)
    """
    
    # Get timestamp for report
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Add logo if provided
    logo_tag = f'<img src="{logo}" width="180"/>' if logo else ""
    
    # Generate HTML report
    parts=[
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>FDA General Principles of Software Validation Static Analysis Report</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; margin: 20px; }",
        "h1 { color: #2c3e50; }",
        "h2 { color: #34495e; margin-top: 30px; border-bottom: 1px solid #eee; padding-bottom: 5px; }",
        "h3 { color: #7f8c8d; margin-top: 20px; }",
        "ul { margin-bottom: 20px; }",
        "li { margin: 5px 0; }",
        "table { border-collapse: collapse; width: 100%; margin: 20px 0; }",
        "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
        "th { background-color: #f2f2f2; }",
        "tr:nth-child(even) { background-color: #f9f9f9; }",
        ".violation { background-color: #ffe6e6; }",
        ".suppression { background-color: #e6ffe6; }",
        ".chart-container { margin: 20px 0; text-align: center; }",
        ".severity-highest { color: #c0392b; font-weight: bold; }",
        ".severity-high { color: #e74c3c; }",
        ".severity-medium { color: #f39c12; }",
        ".severity-low { color: #3498db; }",
        ".severity-lowest { color: #2ecc71; }",
        ".fda-header { background-color: #f8f9fa; padding: 15px; border: 1px solid #e9ecef; margin-bottom: 20px; }",
        ".fda-notice { background-color: #e9f7fe; padding: 10px; border-left: 5px solid #3498db; margin: 15px 0; }",
        ".rules-table { font-size: 0.9em; }",
        ".stats-box { background-color: #f5f7f8; border: 1px solid #ddd; padding: 15px; margin: 15px 0; border-radius: 5px; }",
        ".stats-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px; }",
        ".stat-item { background-color: white; padding: 15px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }",
        ".stat-value { font-size: 24px; font-weight: bold; color: #2c3e50; margin: 10px 0; }",
        ".stat-label { font-size: 14px; color: #7f8c8d; }",
        "</style>",
        "</head><body>",
        f"{logo_tag}<h1>FDA General Principles of Software Validation Static Analysis Report</h1>",
        
        "<div class='fda-header'>",
        "<h2>Device Information</h2>",
        "<table>",
        "".join(f"<tr><td><b>{k}</b></td><td>{v}</td></tr>" for k, v in user.items()),
        f"<tr><td><b>Analysis Date</b></td><td>{timestamp}</td></tr>",
        "</table>",
        
        "<div class='fda-notice'>",
        "<p><strong>Note:</strong> This report was generated using static code analysis as part of the FDA General Principles of Software Validation Report submission process. ",
        "The complete list of active static analysis rules is provided at the end of this report.</p>",
        "</div>",
        "</div>",
    ]
    
    # Add code metrics section if available
    if repo_info and repo_info.get('total_lines', 0) > 0:
        parts.append("<h2>Source Code Metrics</h2>")
        
        # Add repository path
        repo_path = repo_info.get('repo_path', 'Unknown')
        is_github = repo_info.get('is_github', False)
        
        if is_github:
            parts.append(f"<p>GitHub Repository: <a href='{repo_path}' target='_blank'>{repo_path}</a></p>")
        else:
            parts.append(f"<p>Local Repository: {repo_path}</p>")
            
        # Add metrics in a nice format
        parts.append("<div class='stats-box'>")
        parts.append("<div class='stats-grid'>")
        
        # Total LOC
        parts.append("<div class='stat-item'>")
        parts.append(f"<div class='stat-value'>{repo_info.get('total_lines', 0):,}</div>")
        parts.append("<div class='stat-label'>Lines of Code</div>")
        parts.append("</div>")
        
        # Source Files
        parts.append("<div class='stat-item'>")
        parts.append(f"<div class='stat-value'>{repo_info.get('source_files', 0):,}</div>")
        parts.append("<div class='stat-label'>Source Files</div>")
        parts.append("</div>")
        
        # Avg LOC per file
        avg_loc = 0
        if repo_info.get('source_files', 0) > 0:
            avg_loc = round(repo_info.get('total_lines', 0) / repo_info.get('source_files', 1))
            
        parts.append("<div class='stat-item'>")
        parts.append(f"<div class='stat-value'>{avg_loc:,}</div>")
        parts.append("<div class='stat-label'>Avg. Lines per File</div>")
        parts.append("</div>")
        
        # Analysis Ratio
        total_violations = sum(vc)
        violations_per_kloc = 0
        if repo_info.get('total_lines', 0) > 0:
            violations_per_kloc = round((total_violations * 1000) / repo_info.get('total_lines', 1), 2)
            
        parts.append("<div class='stat-item'>")
        parts.append(f"<div class='stat-value'>{violations_per_kloc}</div>")
        parts.append("<div class='stat-label'>Violations per 1K LOC</div>")
        parts.append("</div>")
        
        parts.append("</div>") # End stats-grid
        
        # Add note if applicable
        if 'note' in repo_info:
            parts.append(f"<p><i>Note: {repo_info['note']}</i></p>")
            
        parts.append("</div>") # End stats-box
    
    # Compliance Summary section
    parts.append("<h2>Compliance Summary</h2>")
    parts.append("<table>")
    parts.append("<tr><th>Severity</th><th>Violations</th><th>Suppressions</th><th>Total</th></tr>")
    
    # Add summary rows for each severity
    total_violations = sum(vc)
    total_suppressions = sum(sc)
    for i in range(4, -1, -1):  # Highest to lowest severity
        sev_class = f"severity-{SEVERITY_LABELS[i].lower()}"
        parts.append(f"<tr class='{sev_class}'><td>{SEVERITY_LABELS[i]}</td><td>{vc[i]}</td><td>{sc[i]}</td><td>{vc[i] + sc[i]}</td></tr>")
    
    # Add total row
    parts.append(f"<tr><td><b>Total</b></td><td><b>{total_violations}</b></td><td><b>{total_suppressions}</b></td><td><b>{total_violations + total_suppressions}</b></td></tr>")
    parts.append("</table>")
    
    # Add progress chart
    parts.append("<div class='chart-container'>")
    parts.append(f"<h2>Historical Progress Chart</h2>")
    parts.append(f"<p>This chart shows the progress of static analysis violations over time.</p>")
    parts.append(f"<img src='{os.path.basename(png)}' width='800'/>")
    parts.append("</div>")
    
    # Violation details section
    parts.append("<h2>Violation Details</h2>")
    if total_violations == 0:
        parts.append("<p>No violations found.</p>")
    else:
        parts.append("<table>")
        parts.append("<tr><th>Severity</th><th>Line</th><th>Message</th><th>Rule</th></tr>")
        
        for sev in range(4, -1, -1):  # Highest to lowest severity
            for ln, msg, rule in vd.get(sev, []):
                sev_class = f"severity-{SEVERITY_LABELS[sev].lower()}"
                parts.append(f"<tr class='violation {sev_class}'>")
                parts.append(f"<td>{SEVERITY_LABELS[sev]}</td><td>{ln}</td><td>{msg}</td><td>{rule}</td>")
                parts.append("</tr>")
        
        parts.append("</table>")
    
    # Suppression details section
    parts.append("<h2>Suppression Details</h2>")
    total_suppressions = sum(sc)
    if total_suppressions == 0:
        parts.append("<p>No suppressions found. No .suppress file was provided or it contains no suppressions.</p>")
    else:
        parts.append("<p>The following suppressions were defined in the .suppress file:</p>")
        parts.append("<table>")
        parts.append("<tr><th>Severity</th><th>File</th><th>Line</th><th>Rule ID</th><th>Message</th><th>Reason</th><th>Author</th></tr>")
        
        for sev in range(4, -1, -1):  # Highest to lowest severity
            for ln, msg, rule in sd.get(sev, []):
                sev_class = f"severity-{SEVERITY_LABELS[sev].lower()}"
                
                # Extract file path if present in the message
                file_path = ""
                message = msg
                reason = ""
                author = ""
                
                # Parse out file path if present
                if ": " in msg:
                    parts_msg = msg.split(": ", 1)
                    file_path = parts_msg[0]
                    message = parts_msg[1]
                
                # Extract reason if provided in message
                if "(Reason: " in message:
                    message, reason_part = message.split("(Reason: ", 1)
                    reason = reason_part.rstrip(")")
                
                parts.append(f"<tr class='suppression {sev_class}'>")
                parts.append(f"<td>{SEVERITY_LABELS[sev]}</td>")
                parts.append(f"<td>{file_path}</td>")
                parts.append(f"<td>{ln}</td>")
                parts.append(f"<td>{rule}</td>")
                parts.append(f"<td>{message}</td>")
                parts.append(f"<td>{reason}</td>")
                parts.append(f"<td>{author}</td>")
                parts.append("</tr>")
        
        parts.append("</table>")
        
        # Add explanation about suppressions
        parts.append("<div class='fda-notice'>")
        parts.append("<p><strong>Note on Suppressions:</strong> Suppressions are violations that have been explicitly " +
                    "excluded from causing certification failures. Each suppression should have a documented reason " +
                    "and be approved by the project lead or designated authority.</p>")
        parts.append("</div>")
    
    # Active Rules Section
    parts.append("<h2>Active Static Analysis Rules</h2>")
    
    if rules_list:
        parts.append("<p>The following rules were active during the static analysis:</p>")
        parts.append("<table class='rules-table'>")
        parts.append("<tr><th>Rule ID</th><th>Description</th><th>Category</th><th>Severity</th></tr>")
        
        # Group rules by category
        rules_by_category = {}
        for rule in rules_list:
            category = rule['category']
            if category not in rules_by_category:
                rules_by_category[category] = []
            rules_by_category[category].append(rule)
        
        # Add rules to table by category
        for category, rules in sorted(rules_by_category.items()):
            parts.append(f"<tr><td colspan='4'><strong>{category}</strong></td></tr>")
            
            for rule in sorted(rules, key=lambda r: r['id']):
                rule_id = rule['id']
                description = rule['description']
                severity = SEVERITY_LABELS[min(max(0, rule['severity']), 4)]
                sev_class = f"severity-{severity.lower()}"
                
                parts.append(f"<tr>")
                parts.append(f"<td>{rule_id}</td><td>{description}</td><td>{category}</td>")
                parts.append(f"<td class='{sev_class}'>{severity}</td>")
                parts.append("</tr>")
        
        parts.append("</table>")
    else:
        parts.append("<p>No detailed rule information available. Analysis was performed using the standard set of rules specified in the device information.</p>")
    
    # Add footer and close HTML
    parts.append("<hr>")
    parts.append("<div class='fda-notice'>")
    parts.append(f"<p><strong>FDA General Principles of Software Validation Static Analysis Report</strong> generated on {timestamp}</p>")
    parts.append(f"<p>This report is part of the FDA General Principles of Software Validation Report submission for {user.get('Device Name', 'the device')} (SW Version: {user.get('Software Version', 'N/A')})</p>")
    parts.append("</div>")
    parts.append("</body></html>")
    
    # Write HTML file
    with open(out_html, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))


# GUI
def _get_report(prompt): 
    """Show file dialog to select a report."""
    return filedialog.askopenfilename(title=prompt)


def get_inputs(): 
    """Get device and analysis information from user."""
    device_info = {}
    fields = [
        "Device Name", 
        "Manufacturer",
        "FDA General Principles of Software Validation Report Number",
        "Contact Info",
        "Software Version",
    ]
    
    # Get basic device info
    for field in fields:
        device_info[field] = simpledialog.askstring("Input", f"Enter {field}:") or ""
    
    # Get tool information with defaults - using the new text
    device_info["Static Code Analysis tool used"] = simpledialog.askstring(
        "Input", 
        "Enter Static Code Analysis tool used:", #added for clarity 
        initialvalue="Parasoft C++TEST"
    ) or "Parasoft C++TEST"
    
    device_info["Tool Version"] = simpledialog.askstring(
        "Input", 
        "Enter Tool Version:", 
        initialvalue="2024.2"
    ) or "2024.2"
    
    device_info["Rules Standard"] = simpledialog.askstring(
        "Input", 
        "Enter Rules Standard:", 
        initialvalue="General Principles of Software Validation-MISRA C 2023 based3"
    ) or "General Principles of Software Validation-MISRA C 2023 based"
    
    return device_info


def run():
    """Main function to run the report generator."""
    try:
        # Get the current report
        cur_p = _get_report("Select CURRENT report (XML or HTML)")
        if not cur_p: 
            return
        
        print(f"Processing current report: {cur_p}")
        vc, vd, rules_list, tool_info = load(cur_p)
        
        # Ask for suppression file
        supp_p = _get_report("Select suppression file (.suppress)")
        
        # Initialize suppression data structures
        sc = [0]*5  # Suppression counts by severity
        sd = {i: [] for i in range(5)}  # Suppression details by severity
        
        # Parse suppression file if provided
        if supp_p:
            print(f"Processing suppression file: {supp_p}")
            suppressions = parse_suppression_file(supp_p)
            
            # Process suppressions by severity
            for supp in suppressions:
                severity = supp.get('severity', 2)  # Default to medium
                sc[severity] += 1
                
                # Format suppression details
                line = supp.get('line', 'N/A')
                file_path = supp.get('file', '')
                message = supp.get('message', '')
                rule_id = supp.get('rule-id', '')
                reason = supp.get('reason', '')
                author = supp.get('author', '')
                
                formatted_msg = f"{file_path}: {message}"
                if reason:
                    formatted_msg += f" (Reason: {reason})"
                
                sd[severity].append((line, formatted_msg, rule_id))
        
        # Print summary of violations and suppressions for debugging
        print(f"Violations by severity: {vc}")
        print(f"Suppressions by severity: {sc}")
        
        # Analyze repository code
        repo_info = {}
        if messagebox.askyesno("Code Analysis", "Would you like to include source code metrics in the report?"):
            repo_info = get_repository_code_info()
            print(f"Repository code info: {repo_info}")
        
        # History tracking file
        history_file = "analysis_history.json"
        history_data = []
        
        try:
            if os.path.exists(history_file):
                with open(history_file, 'r') as f:
                    history_data = json.load(f)
        except Exception as e:
            print(f"Could not load history file: {e}")
        
        # Get user inputs for device info
        usr = get_inputs()
        
        # Add tool info from report if available
        if tool_info:
            if "name" in tool_info and not usr.get("Static Code Analysis tool used"):#added for clarity 
                usr["Static Code Analysis tool used"] = tool_info["name"]
            if "version" in tool_info and not usr.get("Tool Version"):
                usr["Tool Version"] = tool_info["version"]
            if "rules_standard" in tool_info and not usr.get("Rules Standard"):
                usr["Rules Standard"] = tool_info["rules_standard"]
        
        # Current timestamp
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        date_str = datetime.now().strftime("%Y-%m-%d")
        
        # Check if user wants to add previous reports
        prev_data = []
        add_history = messagebox.askyesno("Historical Data", 
            "Do you want to include historical data (previous reports) in the progress chart?")
        
        if add_history:
            done_adding = False
            while not done_adding:
                prev_p = _get_report("Select a PREVIOUS report (optional, cancel to finish)")
                if not prev_p:
                    done_adding = True
                    continue
                    
                print(f"Processing previous report: {prev_p}")
                try:
                    pvc, _, _, _ = load(prev_p)
                    
                    # Ask for the date of this previous report
                    prev_date = simpledialog.askstring("Previous Report Date", 
                        "Enter the date for this previous report (YYYY-MM-DD):",
                        initialvalue=datetime.now().strftime("%Y-%m-%d"))
                    
                    if prev_date:
                        prev_data.append((prev_date, pvc))
                except Exception as e:
                    messagebox.showerror("Error", f"Could not process previous report: {e}")
        
        # Update history data with current report
        history_entry = {
            "date": date_str,
            "violations": vc,
            "suppressions": sc, 
            "total": [vc[i] + sc[i] for i in range(5)]
        }
        history_data.append(history_entry)
        
        # Save updated history
        try:
            with open(history_file, 'w') as f:
                json.dump(history_data, f, indent=2)
        except Exception as e:
            print(f"Could not save history file: {e}")
        
        # Allow user to select output directory
        output_dir = filedialog.askdirectory(title="Select output directory for reports")
        if not output_dir:
            # User cancelled, use default directory
            # Use a safe device name for folder creation
            safe_device_name = usr["Device Name"].replace(" ", "_") if usr["Device Name"] else "Unknown_Device"
            output_dir = os.path.join("Reports", safe_device_name)
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Get logo if desired
        logo_file = ""
        logo_in = filedialog.askopenfilename(title="Select logo (optional)", filetypes=[("Images","*.png;*.jpg;*.jpeg")])
        if logo_in: 
            logo_file = os.path.join(output_dir, "logo" + os.path.splitext(logo_in)[1])
            shutil.copyfile(logo_in, logo_file)
        
        # Base filenames
        report_basename = f"FDA_General_Principles_of_Software_Validation_Report_{usr['Device Name'].replace(' ', '_')}_{ts}" if usr["Device Name"] else f"FDA_General_Principles_of_Software_Validation_{ts}"
        
        # Paths for output files
        png = os.path.join(output_dir, f"chart_{ts}.png")
        out_html = os.path.join(output_dir, f"{report_basename}.html")
        
        # Create progress chart with historical data
        create_historical_chart(vc, prev_data, png)
        
        # Generate HTML report with additional information
        generate_html(usr, vc, [], vd, png, os.path.basename(logo_file) if logo_file else "", 
                      out_html, sc, sd, rules_list, repo_info)
        
        # Show completion message
        output_files = f"Reports saved to: {output_dir}\n\nFiles:\n{os.path.basename(out_html)}"
        
        messagebox.showinfo("Done", output_files)
        
        # Option to open the report
        if messagebox.askyesno("Open Report", "Would you like to open the HTML report now?"):
            try:
                webbrowser.open(out_html)
            except Exception as e:
                messagebox.showerror("Error", f"Could not open report: {e}")
    
    except Exception as e:
        import traceback
        error_message = f"An error occurred during report generation:\n\n{str(e)}"
        print(error_message)
        traceback.print_exc()
        messagebox.showerror("Error", error_message)


# Main application window
def main():
    """Create the main application window."""
    root = tk.Tk()
    root.title("FDA Parasoft Report Viewer")
    root.geometry("600x400")
    
    # Set application icon if available
    try:
        # Attempt to set an icon if one exists
        if os.path.exists("icon.ico"):
            root.iconbitmap("icon.ico")
    except Exception:
        pass  # Ignore if icon setting fails
        
    # Main frame
    main_frame = ttk.Frame(root, padding="20")
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # Application title
    ttk.Label(main_frame, text="FDA Parasoft Report Viewer", font=("Arial", 16, "bold")).pack(pady=10)
    ttk.Label(main_frame, text="Generate FDA General Principles of Software Validation reports from Parasoft C/C++test results", 
              wraplength=500).pack(pady=5)
    
    # Add version information
    version_text = "Version 1.1.0"
    ttk.Label(main_frame, text=version_text, font=("Arial", 8)).pack(pady=2)
    
    # Separation line
    separator = ttk.Separator(main_frame, orient='horizontal')
    separator.pack(fill='x', padx=20, pady=15)
    
    # Instructions
    instructions = (
        "This tool processes Parasoft C/C++test HTML or XML reports and "
        "generates FDA-style documentation showing violations and suppressions "
        "with detailed statistics and progress charts.\n\n"
        "Suppressions are read from a separate .suppress file, not from the report. "
        "Source code metrics can be included from a local or GitHub repository."
    )
    ttk.Label(main_frame, text=instructions, wraplength=500, justify="center").pack(pady=10)
    
    # Action buttons frame
    button_frame = ttk.Frame(main_frame)
    button_frame.pack(pady=20)
    
    # Generate report button
    generate_btn = ttk.Button(
        button_frame, 
        text="Generate Report", 
        command=lambda: [root.withdraw(), run(), root.deiconify()]
    )
    generate_btn.grid(row=0, column=0, padx=10)
    
    # Exit button
    exit_btn = ttk.Button(
        button_frame, 
        text="Exit", 
        command=root.destroy
    )
    exit_btn.grid(row=0, column=1, padx=10)
    
    # Footer//Dani Backup
    footer_text = "© 2025 FDA General Principles of Software Validation Documentation Tools"
    ttk.Label(main_frame, text=footer_text, font=("Arial", 8)).pack(side=tk.BOTTOM, pady=10)
    
    # Center the window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    
    # Start the main loop
    root.mainloop()


# Execute main function when script is run directly 
if __name__ == "__main__":
    main()
    #General Principles of Software Validation-MISRA C 2023 based as deafult 