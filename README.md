# General Parasoft Report Viewer

## Overview

General Parasoft Report Viewer is a versatile tool designed to process Parasoft C/C++test static analysis reports and generate comprehensive documentation. It parses both HTML and XML reports from Parasoft, extracts violations, and incorporates suppressions from separate suppression files to produce detailed static analysis documentation suitable for any organization or project.

## Key Features

- **Violation Analysis**: Extracts violations from Parasoft C/C++test HTML or XML reports
- **Suppression Management**: Reads suppressions from Parasoft .suppress files, maintaining clear separation between violations and approved suppressions
- **Severity Classification**: Automatically determines severity levels for violations and suppressions
- **Historical Tracking**: Maintains and visualizes violation trends over time to demonstrate progress
- **Professional Reporting**: Formats reports according to professional documentation standards
- **Rule Documentation**: Extracts and includes complete list of active static analysis rules
- **Customizable Output**: Allows selection of output directory and company logo incorporation
- **Source Code Metrics**: Optional inclusion of repository code metrics (local or GitHub)

## Requirements

- Python 3.8 or higher
- Required packages:
  - lxml (XML parsing)
  - matplotlib (chart generation)
  - pillow (image processing)
  - beautifulsoup4 (HTML parsing)
  - requests (optional, for GitHub repository analysis)

## Installation

1. Clone or download this repository
2. Install required packages:
   ```
   pip install lxml matplotlib pillow beautifulsoup4 requests
   ```

## Usage

1. Run the application:
   ```
   python General_Parasoft_Report.py
   ```

2. Through the GUI, you will be prompted to:
   - Select a Parasoft report file (XML or HTML)
   - Select a .suppress file containing suppression definitions (optional)
   - Enter software/project information for the report
   - Add historical report data (optional)
   - Choose an output directory
   - Add a company logo (optional)
   - Include source code metrics (optional)

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

- Software/project information
- Analysis summary with violations and suppressions by severity
- Source code metrics (if provided)
- Historical progress charts
- Detailed violation listings
- Suppression details with justifications
- Complete active rules documentation

## Visual Studio 2022 Support

This project includes Visual Studio 2022 project files:
- `General_Parasoft_Report.sln` - Solution file
- `General_Parasoft_Report.pyproj` - Python project file

To open in Visual Studio 2022:
1. Ensure Python development workload is installed
2. Open `General_Parasoft_Report.sln`
3. Set `General_Parasoft_Report.py` as startup file
4. Run or debug the application

## Integration Examples

### Automated Build Integration
```batch
REM Example batch file for CI/CD integration
python General_Parasoft_Report.py --automated --report analysis_output.xml --suppressions suppressions.suppress --output reports/
```

### Script Integration
```bash
#!/bin/bash
# Generate reports automatically
python General_Parasoft_Report.py --batch-mode \
    --report "$1" \
    --suppressions "$2" \
    --project-name "My Project" \
    --version "1.0.0"
```

## Configuration

The application supports command-line arguments for automated usage:
- `--report`: Path to Parasoft report file
- `--suppressions`: Path to suppressions file
- `--output`: Output directory
- `--project-name`: Software/project name
- `--version`: Software version

## Customization

### Adding New Rule Categories
1. Modify the `_detect_severity()` function in the main script
2. Add new severity detection patterns
3. Update the HTML generation templates

### Custom Report Templates
1. Modify the `generate_html()` function
2. Customize CSS styles in the HTML template
3. Add new sections or modify existing layouts

## Troubleshooting

### Common Issues

1. **Missing Dependencies**: Install all required Python packages
2. **File Access Errors**: Ensure proper file permissions
3. **Encoding Issues**: Files should be UTF-8 encoded
4. **Report Parsing Errors**: Verify Parasoft report format compatibility

### Debug Mode

Run with debug output:
```python
python General_Parasoft_Report.py --debug
```

## Changes from Original FDA Version

This general version includes the following modifications:
- Removed all FDA-specific terminology and references
- Generalized field names (e.g., "FDA Report Number" → "Report Number")
- Updated documentation to be applicable to any organization
- Modified HTML templates for general professional use
- Changed application title and branding
- Updated default rule standards to be more generic

## License

This project is provided as-is for educational and professional use.

## Contributing

Contributions to improve the General Parasoft Report Viewer are welcome. Please feel free to submit a pull request or open an issue to discuss potential changes or enhancements.

## Version History

- **2.0.0** - General Edition: Removed FDA-specific references, added general professional reporting
- **1.1.5** - Original FDA-specific version
