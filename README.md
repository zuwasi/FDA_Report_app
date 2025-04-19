# FDA_Report_generator
An application that takes standard Parasoft Static Analysis reports and turn them to 510 (k) Static Analysis ready reports 
# FDA Parasoft Report Viewer

## Overview

FDA Parasoft Report Viewer is a specialized tool designed to process Parasoft C/C++test static analysis reports and generate FDA K510-compliant documentation. It parses both HTML and XML reports from Parasoft, extracts violations, and incorporates suppressions from separate suppression files to produce comprehensive static analysis documentation suitable for FDA submissions.

## Key Features

- **Violation Analysis**: Extracts violations from Parasoft C/C++test HTML or XML reports
- **Suppression Management**: Reads suppressions from Parasoft .suppress files, maintaining clear separation between violations and approved suppressions
- **Severity Classification**: Automatically determines severity levels for violations and suppressions
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
   python fda_report_app.py
   ```

2. Through the GUI, you will be prompted to:
   - Select a Parasoft report file (XML or HTML)
   - Select a .suppress file containing suppression definitions
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
- Detailed violation listings
- Suppression details with justifications
- Complete active rules documentation

## License

MIT License 

## Contributing

Contributions to improve the FDA Parasoft Report Viewer are welcome. Please feel free to submit a pull request or open an issue to discuss potential changes or enhancements.
