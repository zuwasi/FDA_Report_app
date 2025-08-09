# Enhanced FDA Report Generator
An enhanced application that takes standard Parasoft Static Analysis reports and turns them into 510(k) Static Analysis ready reports with advanced filtering and scanning capabilities.

# Enhanced FDA Parasoft Report Viewer

## Overview

Enhanced FDA Parasoft Report Viewer is an advanced version of the specialized tool designed to process Parasoft C/C++test static analysis reports and generate FDA K510-compliant documentation. It parses both HTML and XML reports from Parasoft, extracts violations, and incorporates suppressions from separate suppression files to produce comprehensive static analysis documentation suitable for FDA submissions.

This enhanced version includes new features for better violation management and improved report accuracy.

## Key Features

### Enhanced Features (New in this version):
- **Directory Exclusion**: Allows users to select directories that will be excluded from the final HTML report
- **Project-wide Suppression Scanning**: Automatically scans entire project directories for all .suppress files matching the pattern "parasoft.suppress"
- **Improved Severity Detection**: Better handling of "Highest" severity level violations in HTML output
- **Advanced Filtering**: Violations and suppressions from excluded directories are filtered out
- **Enhanced File Path Display**: Shows file paths in clean format (\\directory\\name.c/h/cpp) with separate columns for better readability

### Core Features:
- **Violation Analysis**: Extracts violations from Parasoft C/C++test HTML or XML reports
- **Suppression Management**: Reads suppressions from Parasoft .suppress files, maintaining clear separation between violations and approved suppressions
- **Severity Classification**: Automatically determines severity levels for violations and suppressions with improved "Highest" level detection
- **Historical Tracking**: Maintains and visualizes violation trends over time to demonstrate progress
- **FDA K510 Compliance**: Formats reports according to FDA documentation standards
- **Rule Documentation**: Extracts and includes complete list of active static analysis rules
- **Customizable Output**: Allows selection of output directory and company logo incorporation

## Requirements

- Python 3.8 or higher
- Required packages:
  - lxml (XML parsing)
  - matplotlib (chart generation)
  - pillow (image processing)
  - beautifulsoup4 (HTML parsing)

## Installation

1. Clone this repository
2. Install required packages:
   ```
   pip install lxml matplotlib pillow beautifulsoup4
   ```

## Usage

1. Run the application:
   ```
   python Enhanced_FDA_Report_app.py
   ```

2. Through the GUI, you will be prompted to:
   - **NEW**: Select directories to exclude from the report (optional)
   - Select a Parasoft report file (XML or HTML)
   - **NEW**: Option to scan a project directory for all .suppress files, or select individual files
   - Enter device and software information for the report
   - Add historical report data (optional)
   - Choose an output directory
   - Add a company logo (optional)

3. The application will generate:
   - An HTML report documenting violations and suppressions
   - Historical progress charts showing violation trends over time

## File Formats

### Suppression Files

The application accepts Parasoft .suppress files with the following format:

```
suppression-begin
file: filename.c
line: 123
rule-id: RULE_ID
message: Violation message
reason: Justification for suppression
author: Developer name
suppression-end
```

## Generated Reports

The generated HTML reports include:

- Device and software information
- Compliance summary with violations and suppressions by severity
- Historical progress charts
- Detailed violation listings with clearly formatted file paths (\\directory\\name.extension)
- Suppression details with justifications and file path information
- Complete active rules documentation

## License

MIT License 

## Contributing

Contributions to improve the FDA Parasoft Report Viewer are welcome. Please feel free to submit a pull request or open an issue to discuss potential changes or enhancements.
