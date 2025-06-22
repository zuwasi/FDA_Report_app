FDA Report App - Static Analysis Report Generator
A Python application that processes Parasoft C/C++test static analysis reports and generates FDA General Principles of Software Validation compliant documentation with detailed statistics, progress tracking, and professional HTML reports.

Overview
The FDA Report App is designed to help medical device software developers create comprehensive static analysis documentation required for FDA submissions. It processes Parasoft C/C++test reports (HTML or XML format), analyzes suppression files, and generates professional FDA-style reports with historical progress tracking and source code metrics.

Key Features
📊 Comprehensive Report Generation
Processes both HTML and XML Parasoft C/C++test reports
Separates actual violations from suppressed items
Generates professional FDA-compliant HTML reports
Includes device information, compliance summaries, and detailed violation/suppression analysis
📈 Historical Progress Tracking
Maintains analysis history in JSON format
Creates progress charts showing violation trends over time
Includes trendlines for better visualization of improvement efforts
Supports adding multiple previous reports for comprehensive tracking
🔍 Source Code Metrics Analysis
Local Repository Analysis: Counts lines of code in C/C++ source files
GitHub Integration: Analyzes repositories directly from GitHub URLs using API
Automatic Git Cloning: Falls back to cloning if API limits are reached
Code Quality Metrics: Calculates violations per 1K lines of code
🎯 Intelligent Severity Detection
Automatically categorizes violations by severity (Lowest, Low, Medium, High, Highest)
Uses rule IDs, keywords, and function patterns for accurate classification
Supports custom severity mapping for different coding standards
📋 Suppression Management
Parses .suppress files to extract suppression details
Tracks suppression reasons, authors, and approval status
Provides clear separation between active violations and approved suppressions
Includes suppression justification in final reports
🖥️ User-Friendly GUI
Intuitive tkinter-based interface
Step-by-step wizard for report generation
File dialogs for easy file selection
Progress indicators and cancellation support
System Requirements
Python: 3.8 or higher
Operating System: Windows, macOS, or Linux
Memory: 512MB RAM minimum (more recommended for large codebases)
Storage: 100MB free space for reports and temporary files
Dependencies
pip install lxml matplotlib pillow beautifulsoup4 requests

Required Packages:
lxml - XML processing
matplotlib - Chart generation
pillow - Image processing
beautifulsoup4 - HTML parsing
requests - GitHub API integration (optional)
Installation
Clone the Repository

git clone https://github.com/zuwasi/FDA_Report_app.git
cd FDA_Report_app

Install Dependencies

pip install -r requirements.txt

Or manually:

pip install lxml matplotlib pillow beautifulsoup4 requests

Run the Application

python FDA_Report_app.py

Usage Guide
1. Launch the Application
Run the script to open the GUI interface:

python FDA_Report_app.py

2. Generate Report Workflow
Click "Generate Report"
Select your current Parasoft report (XML or HTML)
Optionally select a suppression file (.suppress)
Choose whether to include source code metrics
Add historical reports for progress tracking
Enter device and project information
Select output directory and optional logo
Review generated HTML report
3. Input File Formats
Parasoft Reports
XML reports from C/C++test
HTML reports from static analysis runs
Both desktop and server-generated reports supported
Suppression Files
suppression-begin
rule-id: MISRAC2023-8_2_a
file: src/main.c
line: 42
message: Unused parameter 'argc'
reason: Required by main() signature
author: john.doe
suppression-end

4. Repository Analysis Options
Local Directory: Browse and select local source code folder
GitHub Repository: Enter repository URL (e.g., https://github.com/user/repo)
Automatic Analysis: Counts C/C++ source files and calculates metrics
Output Files
The application generates several files in your chosen output directory:

FDA_General_Principles_of_Software_Validation_Report_[Device]_[Timestamp].html - Main report
chart_[Timestamp].png - Historical progress chart
logo.[ext] - Copied logo file (if provided)
analysis_history.json - Historical data for future runs
Technical Architecture
Core Components
Report Parsers (parse_html_report, parse_xml_report)

BeautifulSoup for HTML parsing
lxml for XML processing
Extracts violations, rules, and metadata
Suppression Handler (parse_suppression_file)

Parses Parasoft .suppress files
Categorizes suppressions by severity
Maintains suppression justifications
Code Analysis Engine (count_lines_in_directory, try_fetch_github_api)

Local file system analysis
GitHub API integration
Git repository cloning fallback
Report Generator (generate_html)

Professional HTML template
Embedded CSS styling
Responsive design for various devices
Chart Creation (create_historical_chart)

Matplotlib-based visualization
Historical trend analysis
Severity-based color coding
Data Flow
Parasoft Report → Parser → Violation Data
Suppression File → Parser → Suppression Data
Source Code → Analyzer → Metrics Data
Historical Data → Tracker → Progress Data
All Data → Generator → FDA HTML Report

Supported Standards
MISRA C 2023
MISRA C++ 2023
Custom Parasoft Rule Sets
FDA General Principles of Software Validation
IEC 62304 (Medical Device Software)
Configuration Options
Severity Mapping
The application automatically detects severity levels based on:

Rule ID patterns (_2_, _3_ for high severity)
Function patterns (strcpy, malloc for high severity)
Keyword analysis (unused, declaration for low severity)
Chart Customization
Historical data points
Trendline analysis
Color-coded severity levels
Export formats (PNG, configurable DPI)
Troubleshooting
Common Issues
Import Errors

pip install --upgrade lxml matplotlib pillow beautifulsoup4 requests

GitHub API Rate Limits

Application automatically falls back to Git cloning
Use personal access tokens for higher limits
Large Repository Analysis

API method limits to 100 files to avoid timeouts
Git cloning method analyzes complete repository
Memory Issues with Large Reports

Split large reports into smaller chunks
Increase system memory allocation
Contributing
We welcome contributions! Please see our Contributing Guidelines for details.

Development Setup
git clone https://github.com/zuwasi/FDA_Report_app.git
cd FDA_Report_app
pip install -r requirements-dev.txt

Areas for Contribution
Additional static analysis tool support
Enhanced chart visualizations
Mobile-responsive report templates
Integration with CI/CD pipelines
Docker containerization
License
This project is licensed under the MIT License - see the LICENSE file for details.

Version History
v1.1.5 - Current release
GitHub repository integration
Enhanced suppression file parsing
Improved error handling and user experience
Source code metrics analysis
Support
For issues, questions, or contributions:

📧 Create an issue on GitHub
📚 Check the Wiki for detailed documentation
💬 Join our Discussions
Acknowledgments
Built for FDA General Principles of Software Validation compliance
Designed for medical device software development teams
Supports Parasoft C/C++test integration
Inspired by regulatory requirements for static analysis documentation
Note: This tool is designed to assist with FDA documentation requirements but does not guarantee compliance. Always consult with regulatory experts and review all generated reports before submission.
