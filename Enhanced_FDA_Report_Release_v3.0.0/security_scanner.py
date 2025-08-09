#!/usr/bin/env python3
"""
OWASP Top 10 Security Scanner for Enhanced FDA Report App
Analyzes Python code for common security vulnerabilities
"""

import os
import re
import ast
import json
from typing import List, Dict, Any

class SecurityVulnerability:
    def __init__(self, vuln_type: str, severity: str, line: int, code: str, description: str, remediation: str):
        self.vuln_type = vuln_type
        self.severity = severity
        self.line = line
        self.code = code
        self.description = description
        self.remediation = remediation

class OWASPSecurityScanner:
    def __init__(self):
        self.vulnerabilities = []
        
    def scan_file(self, file_path: str) -> List[SecurityVulnerability]:
        """Scan a Python file for OWASP Top 10 vulnerabilities."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
            # Parse AST for deeper analysis
            try:
                tree = ast.parse(content)
                self._analyze_ast(tree, lines)
            except SyntaxError:
                pass  # Skip files with syntax errors
                
            # Pattern-based scanning
            self._scan_patterns(lines)
            
            return self.vulnerabilities
            
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
            return []
    
    def _analyze_ast(self, tree: ast.AST, lines: List[str]):
        """Analyze AST for security vulnerabilities."""
        for node in ast.walk(tree):
            # A01: Broken Access Control
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    # Dangerous functions
                    if node.func.id in ['eval', 'exec', 'compile']:
                        self.vulnerabilities.append(SecurityVulnerability(
                            "A01: Broken Access Control / Code Injection",
                            "HIGH",
                            node.lineno,
                            lines[node.lineno-1].strip() if node.lineno <= len(lines) else "",
                            f"Use of dangerous function '{node.func.id}' can lead to code injection",
                            "Replace with safer alternatives or implement strict input validation"
                        ))
                        
                elif isinstance(node.func, ast.Attribute):
                    # subprocess calls
                    if (isinstance(node.func.value, ast.Name) and 
                        node.func.value.id == 'subprocess' and
                        node.func.attr in ['call', 'run', 'Popen']):
                        
                        # Check for shell=True
                        for keyword in node.keywords:
                            if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant):
                                if keyword.value.value is True:
                                    self.vulnerabilities.append(SecurityVulnerability(
                                        "A03: Injection / Command Injection",
                                        "HIGH",
                                        node.lineno,
                                        lines[node.lineno-1].strip() if node.lineno <= len(lines) else "",
                                        "subprocess call with shell=True can lead to command injection",
                                        "Use shell=False and pass arguments as a list"
                                    ))
                    
                    # os.system calls
                    if (isinstance(node.func.value, ast.Name) and 
                        node.func.value.id == 'os' and
                        node.func.attr == 'system'):
                        self.vulnerabilities.append(SecurityVulnerability(
                            "A03: Injection / Command Injection",
                            "HIGH",
                            node.lineno,
                            lines[node.lineno-1].strip() if node.lineno <= len(lines) else "",
                            "os.system() can lead to command injection vulnerabilities",
                            "Use subprocess with proper argument sanitization"
                        ))
                        
                    # pickle.load calls
                    if (isinstance(node.func.value, ast.Name) and 
                        node.func.value.id == 'pickle' and
                        node.func.attr in ['load', 'loads']):
                        self.vulnerabilities.append(SecurityVulnerability(
                            "A08: Software and Data Integrity Failures",
                            "HIGH",
                            node.lineno,
                            lines[node.lineno-1].strip() if node.lineno <= len(lines) else "",
                            "pickle.load() can execute arbitrary code during deserialization",
                            "Use safer serialization formats like JSON"
                        ))
    
    def _scan_patterns(self, lines: List[str]):
        """Scan for pattern-based vulnerabilities."""
        for i, line in enumerate(lines, 1):
            line_lower = line.lower().strip()
            
            # A02: Cryptographic Failures - Hardcoded secrets
            secret_patterns = [
                r'password\s*=\s*[\'"][^\'"]+[\'"]',
                r'secret\s*=\s*[\'"][^\'"]+[\'"]',
                r'api_key\s*=\s*[\'"][^\'"]+[\'"]',
                r'token\s*=\s*[\'"][^\'"]+[\'"]'
            ]
            
            for pattern in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.vulnerabilities.append(SecurityVulnerability(
                        "A02: Cryptographic Failures",
                        "MEDIUM",
                        i,
                        line.strip(),
                        "Potential hardcoded secret or credential",
                        "Use environment variables or secure credential storage"
                    ))
            
            # A05: Security Misconfiguration - Debug mode
            if 'debug' in line_lower and ('true' in line_lower or '= 1' in line_lower):
                self.vulnerabilities.append(SecurityVulnerability(
                    "A05: Security Misconfiguration",
                    "LOW",
                    i,
                    line.strip(),
                    "Debug mode enabled in production code",
                    "Disable debug mode in production"
                ))
            
            # A06: Vulnerable Components - SQL queries (though not used in this app)
            sql_patterns = [
                r'execute\s*\(\s*[\'"].*%.*[\'"]',
                r'query\s*\(\s*[\'"].*\+.*[\'"]'
            ]
            
            for pattern in sql_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.vulnerabilities.append(SecurityVulnerability(
                        "A03: Injection / SQL Injection",
                        "HIGH",
                        i,
                        line.strip(),
                        "Potential SQL injection vulnerability",
                        "Use parameterized queries or ORM"
                    ))
            
            # A01: Path Traversal
            if 'open(' in line and ('..' in line or 'path' in line_lower):
                if not any(safe in line for safe in ['os.path.join', 'pathlib', 'secure']):
                    self.vulnerabilities.append(SecurityVulnerability(
                        "A01: Broken Access Control / Path Traversal",
                        "MEDIUM",
                        i,
                        line.strip(),
                        "Potential path traversal vulnerability in file operations",
                        "Validate and sanitize file paths, use os.path.join()"
                    ))
            
            # A07: Identification and Authentication Failures
            if any(weak in line_lower for weak in ['md5', 'sha1']) and 'hash' in line_lower:
                self.vulnerabilities.append(SecurityVulnerability(
                    "A02: Cryptographic Failures",
                    "MEDIUM",
                    i,
                    line.strip(),
                    "Use of weak cryptographic hash function",
                    "Use SHA-256 or stronger hash functions"
                ))
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate security report."""
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        vuln_types = {}
        
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] += 1
            if vuln.vuln_type not in vuln_types:
                vuln_types[vuln.vuln_type] = 0
            vuln_types[vuln.vuln_type] += 1
        
        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "severity_breakdown": severity_counts,
            "vulnerability_types": vuln_types,
            "vulnerabilities": [
                {
                    "type": v.vuln_type,
                    "severity": v.severity,
                    "line": v.line,
                    "code": v.code,
                    "description": v.description,
                    "remediation": v.remediation
                } for v in self.vulnerabilities
            ]
        }

def scan_enhanced_fda_app():
    """Scan the Enhanced FDA Report App for security vulnerabilities."""
    scanner = OWASPSecurityScanner()
    
    # Scan main application file
    app_file = "Enhanced_FDA_Report_app.py"
    if os.path.exists(app_file):
        print(f"Scanning {app_file}...")
        scanner.scan_file(app_file)
    
    # Generate report
    report = scanner.generate_report()
    
    print("\n" + "="*60)
    print("OWASP TOP 10 SECURITY SCAN REPORT")
    print("Enhanced FDA Report App")
    print("="*60)
    
    print(f"\nTOTAL VULNERABILITIES: {report['total_vulnerabilities']}")
    print(f"HIGH SEVERITY: {report['severity_breakdown']['HIGH']}")
    print(f"MEDIUM SEVERITY: {report['severity_breakdown']['MEDIUM']}")
    print(f"LOW SEVERITY: {report['severity_breakdown']['LOW']}")
    
    if report['vulnerabilities']:
        print("\nVULNERABILITIES FOUND:")
        print("-" * 40)
        
        for vuln in report['vulnerabilities']:
            print(f"\n[{vuln['severity']}] {vuln['type']}")
            print(f"Line {vuln['line']}: {vuln['code']}")
            print(f"Issue: {vuln['description']}")
            print(f"Fix: {vuln['remediation']}")
    else:
        print("\n✅ NO SECURITY VULNERABILITIES FOUND!")
    
    # Save detailed report
    with open("security_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\nDetailed report saved to: security_report.json")
    return report

if __name__ == "__main__":
    scan_enhanced_fda_app()
