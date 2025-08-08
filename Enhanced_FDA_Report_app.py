#!/usr/bin/env python3
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

cancel_flag = False  # Global flag to allow cancelling at any phase


# Constants & helpers
SEVERITY_LABELS = ["Lowest", "Low", "Medium", "High", "Highest"]
SEV_KEYWORDS = {"lowest": 0, "low": 1, "medium": 2, "high": 3, "highest": 4}

# Global variables to store exclusions
excluded_directories = []
excluded_files = []
exclusion_justifications = {}  # Dictionary to store justification for each exclusion

def validate_file_path(file_path: str) -> bool:
    """Validate file path to prevent directory traversal attacks."""
    try:
        # Convert to absolute path and normalize
        abs_path = os.path.abspath(file_path)
        
        # Check for directory traversal patterns
        if '..' in file_path or file_path.startswith('/'):
            return False
            
        # Ensure the file exists and is a file (not directory)
        if not os.path.exists(abs_path):
            return False
            
        if not os.path.isfile(abs_path):
            return False
            
        # Additional security check - ensure path doesn't escape current working directory
        cwd = os.path.abspath(os.getcwd())
        if not abs_path.startswith(cwd):
            # Allow specific directories for reports
            allowed_dirs = [
                os.path.abspath("C:\\Parasoft"),
                os.path.abspath("C:\\Users"),
                os.path.abspath(os.path.expanduser("~"))
            ]
            if not any(abs_path.startswith(allowed_dir) for allowed_dir in allowed_dirs):
                return False
        
        return True
    except Exception:
        return False

def is_file_excluded(file_path: str) -> bool:
    """Check if a file should be excluded based on directory and file exclusions."""
    if not file_path:
        return False
        
    # Normalize the file path for consistent comparison
    normalized_file_path = os.path.normpath(file_path).replace('\\', '/').lower()
    
    # Check directory exclusions
    for excluded_dir in excluded_directories:
        normalized_excluded_dir = os.path.normpath(excluded_dir).replace('\\', '/').lower()
        
        # Ensure directory boundary matching - file must be IN the directory, not just contain the text
        if (normalized_file_path.startswith(normalized_excluded_dir + '/') or 
            normalized_file_path == normalized_excluded_dir or
            ('/' + normalized_excluded_dir + '/') in ('/' + normalized_file_path)):
            return True
    
    # Check file exclusions
    for excluded_file in excluded_files:
        normalized_excluded_file = os.path.normpath(excluded_file).replace('\\', '/').lower()
        
        # Check exact match or if the file path ends with the excluded file
        if (normalized_file_path == normalized_excluded_file or
            normalized_file_path.endswith('/' + normalized_excluded_file.split('/')[-1])):
            return True
    
    return False

def safe_file_open(file_path: str, mode: str = 'r', **kwargs):
    """Safely open a file with path validation."""
    # Allow exceptions for certain safe files in current directory
    safe_files = ['exclusions.json', 'analysis_history.json']
    if os.path.basename(file_path) in safe_files:
        return open(file_path, mode, **kwargs)
        
    if not validate_file_path(file_path):
        raise ValueError(f"Invalid or unsafe file path: {file_path}")
    return open(file_path, mode, **kwargs)

def sanitize_html_input(text: str) -> str:
    """Sanitize user input to prevent XSS attacks in HTML output."""
    if not isinstance(text, str):
        text = str(text)
    
    # Replace HTML special characters
    html_escape_table = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;",
        "/": "&#x2F;"
    }
    
    for char, escape in html_escape_table.items():
        text = text.replace(char, escape)
    
    return text

def save_exclusions():
    """Save exclusions to a JSON file."""
    try:
        exclusions_data = {
            'excluded_directories': excluded_directories,
            'excluded_files': excluded_files,
            'exclusion_justifications': exclusion_justifications
        }
        with safe_file_open('exclusions.json', 'w') as f:
            json.dump(exclusions_data, f, indent=2)
    except Exception as e:
        print(f"Error saving exclusions: {e}")

def load_exclusions():
    """Load exclusions from a JSON file."""
    global excluded_directories, excluded_files, exclusion_justifications
    try:
        if os.path.exists('exclusions.json'):
            with safe_file_open('exclusions.json', 'r') as f:
                exclusions_data = json.load(f)
                excluded_directories = exclusions_data.get('excluded_directories', [])
                excluded_files = exclusions_data.get('excluded_files', [])
                exclusion_justifications = exclusions_data.get('exclusion_justifications', {})
    except Exception as e:
        print(f"Error loading exclusions: {e}")
        excluded_directories = []
        excluded_files = []
        exclusion_justifications = {}


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


def find_all_suppress_files(project_directory):
    """Find all .suppress files in the project directory and its subdirectories.
    
    Args:
        project_directory: Root directory to search for .suppress files
        
    Returns:
        List of paths to all .suppress files found
    """
    suppress_files = []
    
    try:
        for root, dirs, files in os.walk(project_directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not any(excluded_dir in os.path.join(root, d) for excluded_dir in excluded_directories)]
            
            for file in files:
                file_path = os.path.join(root, file)
                # Skip excluded files
                if any(excluded_file in file_path for excluded_file in excluded_files):
                    continue
                if file.endswith('.suppress') or 'parasoft.suppress' in file.lower():
                    suppress_files.append(file_path)
    except Exception as e:
        print(f"Error searching for .suppress files: {e}")
    
    return suppress_files


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
        with safe_file_open(path, 'r', encoding='utf-8') as f:
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
        with safe_file_open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
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
                repo_url = ask_string(
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
        with safe_file_open(path, encoding="utf-8") as f:
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
            
            # Determine severity - use the improved detection function
            sev = _detect_severity(f"{msg} {rule}")
            
            # Additional keyword-based detection for highest severity
            combined_text = f"{msg} {rule}".lower()
            if "highest" in combined_text or "critical" in combined_text or "blocker" in combined_text:
                sev = 4  # Highest
            elif "high" in combined_text:
                sev = 3  # High
            elif "medium" in combined_text:
                sev = 2  # Medium
            elif "low" in combined_text:
                sev = 1  # Low
            elif "lowest" in combined_text or "info" in combined_text:
                sev = 0  # Lowest
            
            # Check if the file should be excluded
            if is_file_excluded(current_file):
                continue  # Skip this violation
            
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
        
        # Process all StdViol and FlowViol elements (standard and flow analysis violations)
        for violation in root.xpath("//StdViol | //FlowViol"):
            try:
                # Extract data from violation
                severity_str = violation.get("sev", "2")
                try:
                    sev_int = int(severity_str)
                    # Parasoft severity mapping: 1=Highest, 2=High, 3=Medium
                    # Convert to our scale: 0=Lowest, 1=Low, 2=Medium, 3=High, 4=Highest
                    if sev_int == 1:
                        severity = 4  # Highest
                    elif sev_int == 2:
                        severity = 3  # High
                    elif sev_int == 3:
                        severity = 2  # Medium
                    else:
                        severity = 2  # Default to medium for other values
                except ValueError:
                    severity = 2  # Default to medium
                
                line_num = violation.get("ln", "0")
                message = violation.get("msg", "")
                rule = violation.get("rule", "")
                file_path = violation.get("locFile", "")
                
                # If file path starts with '/', remove leading slash
                if file_path and file_path.startswith('/'):
                    file_path = file_path[1:]
                
                # Check if the file should be excluded
                if is_file_excluded(file_path):
                    continue
                
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
                    sev_int = int(sev_str)
                    # Parasoft severity mapping: 1=Highest, 2=High, 3=Medium
                    # Convert to our scale: 0=Lowest, 1=Low, 2=Medium, 3=High, 4=Highest
                    if sev_int == 1:
                        severity = 4  # Highest
                    elif sev_int == 2:
                        severity = 3  # High
                    elif sev_int == 3:
                        severity = 2  # Medium
                    else:
                        severity = 2  # Default to medium for other values
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

        # Plot trendline only if we have enough data points and variation
        if len(x) >= 2:
            try:
                # Check if we have any variation in the data
                if len(set(y)) > 1:  # More than one unique value
                    z = np.polyfit(x, y, min(1, len(x) - 1))  # Use linear fit, or constant if only 2 points
                    p = np.poly1d(z)
                    ax.plot(x + offset, p(x), linestyle='--', linewidth=1.5, alpha=0.7)
                else:
                    # If all values are the same, draw a horizontal line
                    ax.axhline(y=y[0], linestyle='--', linewidth=1.5, alpha=0.7)
            except (np.linalg.LinAlgError, np.RankWarning, ValueError) as e:
                # If polynomial fitting fails, skip the trendline for this severity
                print(f"Skipping trendline for {SEVERITY_LABELS[i]} due to: {e}")
                pass

        # Data labels
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, height + 0.5, str(int(height)),
                        ha='center', va='bottom', fontsize=8)

    ax.set_xlabel('Analysis Date')
    ax.set_ylabel('Number of Violations')
    ax.set_title('Historical Progress of Violations by Severity (with Trendlines)')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right')
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(out_png, dpi=150, bbox_inches='tight')
    plt.close()


def format_file_path(file_path):
    """Format file path in the requested format: \\directory\\name.extension
    
    Args:
        file_path: Raw file path from violation/suppression
        
    Returns:
        Formatted file path string
    """
    if not file_path or file_path == 'N/A':
        return 'N/A'
    
    # Normalize path separators to backslashes
    normalized_path = file_path.replace('/', '\\')
    
    # Remove leading slash/backslash if present
    if normalized_path.startswith('\\'):
        normalized_path = normalized_path[1:]
    
    # Ensure it starts with backslash for the requested format
    if normalized_path and not normalized_path.startswith('\\'):
        normalized_path = '\\' + normalized_path
    
    return normalized_path


def extract_file_and_message(combined_msg):
    """Extract file path and message from combined violation message.
    
    Args:
        combined_msg: Combined message in format "filepath: message"
        
    Returns:
        Tuple of (formatted_file_path, clean_message)
    """
    if ': ' in combined_msg:
        file_part, message_part = combined_msg.split(': ', 1)
        formatted_file = format_file_path(file_part)
        return formatted_file, message_part
    else:
        return 'N/A', combined_msg


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
        "code { background-color: #f4f4f4; padding: 2px 4px; border-radius: 3px; font-family: 'Courier New', monospace; font-size: 0.9em; color: #333; }",
        ".file-path { word-break: break-all; max-width: 300px; }",
        "</style>",
        "</head><body>",
        f"{logo_tag}<h1>FDA General Principles of Software Validation Static Analysis Report</h1>",
        
        "<div class='fda-header'>",
        "<h2>Device Information</h2>",
        "<table>",
        "".join(f"<tr><td><b>{sanitize_html_input(k)}</b></td><td>{sanitize_html_input(v)}</td></tr>" for k, v in user.items()),
        f"<tr><td><b>Analysis Date</b></td><td>{timestamp}</td></tr>",
        "</table>",
        
        "<div class='fda-notice'>",
        "<p><strong>Note:</strong> This report was generated using static code analysis as part of the FDA General Principles of Software Validation Report submission process. ",
        "The complete list of active static analysis rules is provided at the end of this report.</p>",
        "</div>",
        "</div>",
    ]
    
    # Add exclusions section if there are any exclusions
    if excluded_directories or excluded_files:
        parts.extend([
            "<div class='stats-box'>",
            "<h2>Excluded Files and Directories</h2>",
            "<p><strong>Note:</strong> The following files and directories have been excluded from this analysis report:</p>",
            "<table>",
            "<tr><th>Type</th><th>Path</th><th>Justification</th></tr>",
        ])
        
        # Add excluded directories
        for directory in excluded_directories:
            justification = exclusion_justifications.get(directory, "No justification provided")
            parts.append(f"<tr><td>Directory</td><td class='file-path'><code>{sanitize_html_input(directory)}</code></td><td>{sanitize_html_input(justification)}</td></tr>")
        
        # Add excluded files
        for file_path in excluded_files:
            justification = exclusion_justifications.get(file_path, "No justification provided")
            parts.append(f"<tr><td>File</td><td class='file-path'><code>{sanitize_html_input(file_path)}</code></td><td>{sanitize_html_input(justification)}</td></tr>")
        
        parts.extend([
            "</table>",
            "</div>",
        ])
    
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
        parts.append("<tr><th>Severity</th><th>File Path</th><th>Line</th><th>Message</th><th>Rule</th></tr>")
        
        for sev in range(4, -1, -1):  # Highest to lowest severity
            for ln, msg, rule in vd.get(sev, []):
                sev_class = f"severity-{SEVERITY_LABELS[sev].lower()}"
                
                # Extract and format file path
                formatted_file_path, clean_message = extract_file_and_message(msg)
                
                parts.append(f"<tr class='violation {sev_class}'>")
                parts.append(f"<td>{SEVERITY_LABELS[sev]}</td>")
                parts.append(f"<td class='file-path'><code>{formatted_file_path}</code></td>")
                parts.append(f"<td>{ln}</td>")
                parts.append(f"<td>{clean_message}</td>")
                parts.append(f"<td>{rule}</td>")
                parts.append("</tr>")
        
        parts.append("</table>")
    
    # Suppression details section
    parts.append("<h2>Suppression Details</h2>")
    total_suppressions = sum(sc)
    if total_suppressions == 0:
        parts.append("<p>No suppressions found. No .suppress file was provided or it contains no suppressions.</p>")
    else:
        parts.append("<p>The following suppressions were defined in the .suppress file(s):</p>")
        parts.append("<table>")
        parts.append("<tr><th>Severity</th><th>File Path</th><th>Line</th><th>Rule ID</th><th>Message</th><th>Reason</th><th>Author</th></tr>")
        
        for sev in range(4, -1, -1):  # Highest to lowest severity
            for ln, msg, rule in sd.get(sev, []):
                sev_class = f"severity-{SEVERITY_LABELS[sev].lower()}"
                
                # Extract and format file path and message
                formatted_file_path, clean_message = extract_file_and_message(msg)
                
                # Extract reason if provided in message
                reason = ""
                author = ""
                message = clean_message
                
                if "(Reason: " in message:
                    message, reason_part = message.split("(Reason: ", 1)
                    reason = reason_part.rstrip(")")
                
                parts.append(f"<tr class='suppression {sev_class}'>")
                parts.append(f"<td>{SEVERITY_LABELS[sev]}</td>")
                parts.append(f"<td class='file-path'><code>{formatted_file_path}</code></td>")
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
    # Validate output HTML path for security
    if '..' in out_html or out_html.startswith('/'):
        raise ValueError("Invalid output HTML path")
    
    with open(out_html, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))


# GUI
def _get_report(prompt): 
    """Show file dialog to select a report."""
    return filedialog.askopenfilename(title=prompt)


def get_inputs(tool_info=None): 
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
        device_info[field] = ask_string("Input", f"Enter {field}:") or ""
    
    # Get tool information with defaults - using the new text
    # Use tool_info from XML if available, otherwise prompt user
    if tool_info and tool_info.get("name"):
        device_info["Static Code Analysis tool used"] = tool_info["name"]
    else:
        device_info["Static Code Analysis tool used"] = ask_string(
            "Input", 
            "Enter Static Code Analysis tool used:", #added for clarity 
            initialvalue="Parasoft C++TEST"
        ) or "Parasoft C++TEST"
    
    if tool_info and tool_info.get("version"):
        device_info["Tool Version"] = tool_info["version"]
    else:
        device_info["Tool Version"] = ask_string(
            "Input", 
            "Enter Tool Version:", 
            initialvalue="2024.2"
        ) or "2024.2"
    
    if tool_info and tool_info.get("rules_standard"):
        device_info["Rules Standard"] = tool_info["rules_standard"]
    else:
        device_info["Rules Standard"] = ask_string(
            "Input", 
            "Enter Rules Standard:", 
            initialvalue="General Principles of Software Validation-MISRA C 2023 based"
        ) or "General Principles of Software Validation-MISRA C 2023 based"
    
    return device_info


def manage_exclusions():
    """Allow user to manage file and directory exclusions with justifications."""
    global excluded_directories, excluded_files, exclusion_justifications
    
    def add_directory():
        """Add a directory to exclude."""
        directory = filedialog.askdirectory(title="Select Directory to Exclude")
        if directory:
            justification = ask_text("Justification Required", 
                                   f"Enter justification for excluding directory:\n{directory}")
            if justification:
                excluded_directories.append(directory)
                exclusion_justifications[directory] = justification
                refresh_lists()
                save_exclusions()
    
    def add_file():
        """Add a file to exclude."""
        file_path = filedialog.askopenfilename(
            title="Select File to Exclude",
            filetypes=[
                ("C/C++ Files", "*.c *.h *.cpp *.hpp *.cc *.cxx"),
                ("All Files", "*.*")
            ]
        )
        if file_path:
            justification = ask_text("Justification Required", 
                                   f"Enter justification for excluding file:\n{file_path}")
            if justification:
                excluded_files.append(file_path)
                exclusion_justifications[file_path] = justification
                refresh_lists()
                save_exclusions()
    
    def remove_exclusion():
        """Remove selected exclusion."""
        selection = exclusions_listbox.curselection()
        if selection:
            index = selection[0]
            all_exclusions = excluded_directories + excluded_files
            if index < len(all_exclusions):
                item = all_exclusions[index]
                if item in excluded_directories:
                    excluded_directories.remove(item)
                else:
                    excluded_files.remove(item)
                del exclusion_justifications[item]
                refresh_lists()
                save_exclusions()
    
    def refresh_lists():
        """Refresh the exclusions listbox."""
        exclusions_listbox.delete(0, tk.END)
        for directory in excluded_directories:
            exclusions_listbox.insert(tk.END, f"[DIR] {directory}")
        for file_path in excluded_files:
            exclusions_listbox.insert(tk.END, f"[FILE] {file_path}")
    
    def show_justification():
        """Show justification for selected exclusion."""
        selection = exclusions_listbox.curselection()
        if selection:
            index = selection[0]
            all_exclusions = excluded_directories + excluded_files
            if index < len(all_exclusions):
                item = all_exclusions[index]
                justification = exclusion_justifications.get(item, "No justification available")
                messagebox.showinfo("Justification", f"Exclusion: {item}\n\nJustification:\n{justification}")
    
    # Create exclusion management dialog
    dialog = tk.Toplevel()
    dialog.title("Manage Exclusions")
    dialog.geometry("800x500")
    dialog.grab_set()
    
    # Main frame
    main_frame = tk.Frame(dialog)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    # Instructions
    tk.Label(main_frame, text="Manage Files and Directories to Exclude from Analysis", 
             font=("Arial", 12, "bold")).pack(pady=(0, 10))
    
    # Listbox for exclusions
    listbox_frame = tk.Frame(main_frame)
    listbox_frame.pack(fill=tk.BOTH, expand=True)
    
    tk.Label(listbox_frame, text="Current Exclusions:").pack(anchor=tk.W)
    
    scrollbar = tk.Scrollbar(listbox_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    exclusions_listbox = tk.Listbox(listbox_frame, yscrollcommand=scrollbar.set)
    exclusions_listbox.pack(fill=tk.BOTH, expand=True)
    scrollbar.config(command=exclusions_listbox.yview)
    
    # Buttons frame
    buttons_frame = tk.Frame(main_frame)
    buttons_frame.pack(fill=tk.X, pady=(10, 0))
    
    tk.Button(buttons_frame, text="Add Directory", command=add_directory).pack(side=tk.LEFT, padx=(0, 5))
    tk.Button(buttons_frame, text="Add File", command=add_file).pack(side=tk.LEFT, padx=(0, 5))
    tk.Button(buttons_frame, text="Remove Selected", command=remove_exclusion).pack(side=tk.LEFT, padx=(0, 5))
    tk.Button(buttons_frame, text="Show Justification", command=show_justification).pack(side=tk.LEFT, padx=(0, 5))
    tk.Button(buttons_frame, text="Done", command=dialog.destroy).pack(side=tk.RIGHT)
    
    # Initialize the list
    refresh_lists()
    
    dialog.wait_window()

def ask_text(title, prompt, initialvalue=""):
    """Ask for multi-line text input."""
    global cancel_flag
    result = [None]
    dialog = tk.Toplevel()
    dialog.title(title)
    dialog.geometry("600x300")
    dialog.grab_set()
    
    tk.Label(dialog, text=prompt, font=("Arial", 12)).pack(pady=10)
    
    text_widget = tk.Text(dialog, font=("Arial", 11), height=8, width=70)
    text_widget.pack(padx=20, pady=5, fill=tk.BOTH, expand=True)
    text_widget.insert(1.0, initialvalue)
    text_widget.focus()
    
    def on_ok(): 
        result[0] = text_widget.get(1.0, tk.END).strip()
        dialog.destroy()
    def on_cancel():
        global cancel_flag
        cancel_flag = True
        dialog.destroy()
    
    button_frame = tk.Frame(dialog)
    button_frame.pack(pady=10)
    tk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=5)
    tk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=5)
    
    dialog.wait_window()
    return result[0]

def ask_string(title, prompt, initialvalue=""): 
    global cancel_flag
    result = [None]
    dialog = tk.Toplevel()
    dialog.title(title)
    dialog.geometry("600x150")
    tk.Label(dialog, text=prompt, font=("Arial", 12)).pack(pady=10)
    entry_var = tk.StringVar(value=initialvalue)
    entry = tk.Entry(dialog, textvariable=entry_var, font=("Arial", 12), width=50)
    entry.pack(padx=20, pady=5)
    entry.focus()
    def on_ok(): result[0] = entry_var.get(); dialog.destroy()
    def on_cancel():
        global cancel_flag
        cancel_flag = True
        dialog.destroy()
    button_frame = tk.Frame(dialog)
    button_frame.pack(pady=10)
    tk.Button(button_frame, text="OK", width=10, command=on_ok).pack(side="left", padx=10)
    tk.Button(button_frame, text="Cancel", width=10, command=on_cancel).pack(side="right", padx=10)
    dialog.transient()
    dialog.grab_set()
    dialog.wait_window()
    return result[0]



def get_suppress_files_from_project():
    """Allow user to select a project directory and find all .suppress files."""
    global cancel_flag
    
    # Ask if user wants to scan for .suppress files
    scan_project = messagebox.askyesno(
        "Suppression File Scanning",
        "Do you want to scan a project directory for all .suppress files?\n"
        "This will find and include suppressions from all .suppress files in the project."
    )
    
    if not scan_project or cancel_flag:
        return []
    
    # Select project directory
    project_dir = filedialog.askdirectory(title="Select project directory to scan for .suppress files")
    
    if not project_dir or cancel_flag:
        return []
    
    # Find all suppress files
    suppress_files = find_all_suppress_files(project_dir)
    
    if suppress_files:
        messagebox.showinfo(
            "Found Suppression Files",
            f"Found {len(suppress_files)} .suppress files:\n" + 
            "\n".join(f"- {os.path.basename(f)}" for f in suppress_files[:10]) +
            ("\n... and more" if len(suppress_files) > 10 else "")
        )
    else:
        messagebox.showinfo(
            "No Suppression Files Found",
            "No .suppress files were found in the selected directory."
        )
    
    return suppress_files

def run():
    """Main function to run the report generator."""
    global cancel_flag
    try:
        # Load saved exclusions (managed through the "Manage Exclusions" interface)
        load_exclusions()
        
        # Get the current report
        cur_p = _get_report("Select CURRENT report (XML or HTML)")
        if cancel_flag:
            messagebox.showinfo('Cancelled', 'Report generation cancelled.')
            return
        if not cur_p: 
            return
        
        print(f"Processing current report: {cur_p}")
        vc, vd, rules_list, tool_info = load(cur_p)
        
        # Initialize suppression data structures
        sc = [0]*5  # Suppression counts by severity
        sd = {i: [] for i in range(5)}  # Suppression details by severity
        
        # First, try to get suppress files from project scan
        suppress_files = get_suppress_files_from_project()
        if cancel_flag:
            messagebox.showinfo('Cancelled', 'Report generation cancelled.')
            return
        
        # If no project scan was done or no files found, ask for individual file
        if not suppress_files:
            supp_p = _get_report("Select suppression file (.suppress)")
            if cancel_flag:
                messagebox.showinfo('Cancelled', 'Report generation cancelled.')
                return
            if supp_p:
                suppress_files = [supp_p]
        
        # Parse all suppression files
        all_suppressions = []
        for supp_file in suppress_files:
            print(f"Processing suppression file: {supp_file}")
            suppressions = parse_suppression_file(supp_file)
            all_suppressions.extend(suppressions)
        
        # Process suppressions by severity
        for supp in all_suppressions:
            # Check if the suppression file is in an excluded directory
            file_path = supp.get('file', '')
            if any(excluded_dir in file_path for excluded_dir in excluded_directories):
                continue  # Skip this suppression
            
            severity = supp.get('severity', 2)  # Default to medium
            sc[severity] += 1
            
            # Format suppression details
            line = supp.get('line', 'N/A')
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
            if cancel_flag:
                messagebox.showinfo('Cancelled', 'Report generation cancelled.')
                return
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
        usr = get_inputs(tool_info)
        if cancel_flag:
            messagebox.showinfo('Cancelled', 'Report generation cancelled.')
            return
        
        # Tool info is now handled directly in get_inputs() function
        
        # Current timestamp
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        date_str = datetime.now().strftime("%Y-%m-%d")
        
        # Check if user wants to add previous reports
        prev_data = []
        add_history = messagebox.askyesno("Historical Data",
            "Do you want to include historical data (previous reports) in the progress chart?")
        if cancel_flag:
            messagebox.showinfo('Cancelled', 'Report generation cancelled.')
            return 
        
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
                    prev_date = ask_string("Previous Report Date", 
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
        if cancel_flag:
            messagebox.showinfo('Cancelled', 'Report generation cancelled.')
            return
        if not output_dir:
            # User cancelled, use default directory
            # Use a safe device name for folder creation
            safe_device_name = usr["Device Name"].replace(" ", "_") if usr["Device Name"] else "Unknown_Device"
            output_dir = os.path.join("Reports", safe_device_name)
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Get logo if desired
        logo_file = ""
        logo_in = filedialog.askopenfilename(title="Select logo (optional)",
            filetypes=[("Images","*.png;*.jpg;*.jpeg")])
        if cancel_flag:
            messagebox.showinfo('Cancelled', 'Report generation cancelled.')
            return
        if logo_in: 
            logo_file = os.path.join(output_dir, "logo" + os.path.splitext(logo_in)[1])
            # Only copy if source and destination are different
            if os.path.abspath(logo_in) != os.path.abspath(logo_file):
                shutil.copyfile(logo_in, logo_file)
            else:
                # If they're the same, just use the original file
                logo_file = logo_in
        
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
def show_welcome_screen():
    """Show welcome screen with program explanation and logos."""
    welcome = tk.Toplevel()
    welcome.title("Welcome to Parasoft C/C++TEST FDA Reports Generator")
    welcome.geometry("800x700")
    welcome.grab_set()
    
    # Main frame with scrollbar
    main_canvas = tk.Canvas(welcome)
    scrollbar = tk.Scrollbar(welcome, orient="vertical", command=main_canvas.yview)
    scrollable_frame = tk.Frame(main_canvas)
    
    scrollable_frame.bind(
        "<Configure>",
        lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
    )
    
    main_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    main_canvas.configure(yscrollcommand=scrollbar.set)
    
    # Header with logos
    header_frame = tk.Frame(scrollable_frame, bg="white", relief=tk.RAISED, bd=2)
    header_frame.pack(fill=tk.X, padx=10, pady=10)
    
    # Try to add logos (load actual logo files if they exist)
    logo_frame = tk.Frame(header_frame, bg="white")
    logo_frame.pack(pady=20)
    
    # Try to load ESL logo
    try:
        from PIL import Image, ImageTk
        esl_logo_path = r"C:\Parasoft\logos\ESL.png"
        if os.path.exists(esl_logo_path):
            esl_img = Image.open(esl_logo_path)
            esl_img = esl_img.resize((120, 80), Image.Resampling.LANCZOS)
            esl_photo = ImageTk.PhotoImage(esl_img)
            esl_label = tk.Label(logo_frame, image=esl_photo, bg="white")
            esl_label.image = esl_photo  # Keep a reference
            esl_label.pack(side=tk.LEFT, padx=20)
        else:
            # ESL Logo placeholder
            esl_label = tk.Label(logo_frame, text="ESL\nLOGO", bg="lightblue", width=15, height=5, 
                                font=("Arial", 12, "bold"), relief=tk.RAISED, bd=2)
            esl_label.pack(side=tk.LEFT, padx=20)
    except ImportError:
        # Fallback if PIL not available
        esl_label = tk.Label(logo_frame, text="ESL\nLOGO", bg="lightblue", width=15, height=5, 
                            font=("Arial", 12, "bold"), relief=tk.RAISED, bd=2)
        esl_label.pack(side=tk.LEFT, padx=20)
    
    # Try to load Parasoft logo
    try:
        from PIL import Image, ImageTk
        parasoft_logo_path = r"C:\Parasoft\logos\Parasoft Logo.png"
        if os.path.exists(parasoft_logo_path):
            parasoft_img = Image.open(parasoft_logo_path)
            parasoft_img = parasoft_img.resize((120, 80), Image.Resampling.LANCZOS)
            parasoft_photo = ImageTk.PhotoImage(parasoft_img)
            parasoft_label = tk.Label(logo_frame, image=parasoft_photo, bg="white")
            parasoft_label.image = parasoft_photo  # Keep a reference
            parasoft_label.pack(side=tk.LEFT, padx=20)
        else:
            # Parasoft Logo placeholder  
            parasoft_label = tk.Label(logo_frame, text="PARASOFT\nLOGO", bg="lightgreen", width=15, height=5,
                                     font=("Arial", 12, "bold"), relief=tk.RAISED, bd=2)
            parasoft_label.pack(side=tk.LEFT, padx=20)
    except ImportError:
        # Fallback if PIL not available
        parasoft_label = tk.Label(logo_frame, text="PARASOFT\nLOGO", bg="lightgreen", width=15, height=5,
                                 font=("Arial", 12, "bold"), relief=tk.RAISED, bd=2)
        parasoft_label.pack(side=tk.LEFT, padx=20)
    
    # Title
    title_label = tk.Label(scrollable_frame, text="Parasoft C/C++TEST FDA Reports Generator", 
                          font=("Arial", 20, "bold"), fg="#2c3e50")
    title_label.pack(pady=20)
    
    # Subtitle
    subtitle_label = tk.Label(scrollable_frame, 
                             text="Enhanced FDA General Principles of Software Validation Report Generator",
                             font=("Arial", 12), fg="#34495e")
    subtitle_label.pack(pady=5)
    
    # Version
    version_label = tk.Label(scrollable_frame, text="Version 1.2.0", font=("Arial", 10), fg="#7f8c8d")
    version_label.pack(pady=5)
    
    # Main description
    description_text = """
OVERVIEW
This tool processes Parasoft C/C++test HTML or XML reports and generates FDA-style 
documentation showing violations and suppressions with detailed statistics and progress charts.

KEY FEATURES
• Automated tool version detection from XML reports
• Comprehensive file and directory exclusion with justification tracking
• FDA-compliant report generation with violation severity analysis
• Progress tracking with historical data comparison
• Source code metrics integration from local or GitHub repositories
• Professional HTML reports suitable for regulatory submission

EXCLUSION MANAGEMENT
• Exclude specific source files (.c, .h, .cpp, etc.) from analysis
• Exclude entire directories and their subdirectories  
• Mandatory justification text for all exclusions
• Persistent exclusion storage between sessions
• Full transparency - exclusions listed in final report with justifications

REPORT GENERATION PROCESS
1. Select Parasoft XML or HTML report file
2. Configure exclusions (optional) with justifications
3. Enter device and project information
4. Generate comprehensive FDA validation report
5. Review results with charts and detailed violation breakdown

REGULATORY COMPLIANCE
This tool supports FDA General Principles of Software Validation by providing:
• Detailed static analysis documentation
• Traceability of excluded code with justifications
• Professional formatting suitable for regulatory submission
• Historical tracking for validation maintenance

TECHNICAL REQUIREMENTS
• Python 3.8 or higher
• Parasoft C/C++test XML or HTML reports
• Optional: .suppress files for suppression data
• Optional: GitHub access for repository metrics
"""
    
    # Description text widget
    desc_frame = tk.Frame(scrollable_frame)
    desc_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    desc_text = tk.Text(desc_frame, wrap=tk.WORD, font=("Arial", 11), height=25, width=80,
                       bg="#f8f9fa", relief=tk.SUNKEN, bd=1)
    desc_text.pack(fill=tk.BOTH, expand=True)
    desc_text.insert(tk.END, description_text)
    desc_text.config(state=tk.DISABLED)  # Make read-only
    
    # Buttons
    button_frame = tk.Frame(scrollable_frame)
    button_frame.pack(pady=20)
    
    tk.Button(button_frame, text="Continue to Application", 
             font=("Arial", 12, "bold"), bg="#3498db", fg="white",
             command=welcome.destroy, width=20, height=2).pack(side=tk.LEFT, padx=10)
    
    tk.Button(button_frame, text="Exit", 
             font=("Arial", 12), bg="#e74c3c", fg="white",
             command=lambda: [welcome.destroy(), exit()], width=15, height=2).pack(side=tk.LEFT, padx=10)
    
    # Pack canvas and scrollbar
    main_canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    # Center the window
    welcome.update_idletasks()
    width = welcome.winfo_width()
    height = welcome.winfo_height()
    x = (welcome.winfo_screenwidth() // 2) - (width // 2)
    y = (welcome.winfo_screenheight() // 2) - (height // 2)
    welcome.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    
    welcome.wait_window()

def main():
    """Create the main application window."""
    # Load saved exclusions
    load_exclusions()
    
    # Show welcome screen first
    root = tk.Tk()
    root.withdraw()  # Hide main window initially
    show_welcome_screen()
    root.deiconify()  # Show main window after welcome screen
    
    root.title("Parasoft C/C++TEST FDA Reports Generator")
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
    ttk.Label(main_frame, text="Parasoft C/C++TEST FDA Reports Generator", font=("Arial", 16, "bold")).pack(pady=10)
    ttk.Label(main_frame, text="Generate FDA General Principles of Software Validation reports from Parasoft C/C++test results", 
              wraplength=500).pack(pady=5)
    
    # Add version information
    version_text = "Version 1.1.5"
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
        "Source code metrics can be included from a local or GitHub repository.\n\n"
        "Use 'Manage Exclusions' to exclude specific files or directories from "
        "the analysis with justification text that will appear in the report."
    )
    ttk.Label(main_frame, text=instructions, wraplength=500, justify="center").pack(pady=10)
    
    # Action buttons frame
    button_frame = ttk.Frame(main_frame)
    button_frame.pack(pady=20)
    
    # Manage exclusions button
    exclusions_btn = ttk.Button(
        button_frame, 
        text="Manage Exclusions", 
        command=manage_exclusions
    )
    exclusions_btn.grid(row=0, column=0, padx=10)
    
    # Generate report button
    generate_btn = ttk.Button(
        button_frame, 
        text="Generate Report", 
        command=lambda: [root.withdraw(), run(), root.deiconify()]
    )
    generate_btn.grid(row=0, column=1, padx=10)
    
    # Exit button
    exit_btn = ttk.Button(
        button_frame, 
        text="Exit", 
        command=root.destroy
    )
    exit_btn.grid(row=0, column=2, padx=10)
    
    # Footer
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