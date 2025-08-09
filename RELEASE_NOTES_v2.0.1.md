# 🚀 General Parasoft Report Viewer v2.0.1 - Non-FDA Edition

## 📦 Release Information

**Version:** 2.0.1 - General Edition  
**Release Date:** January 8, 2025  
**Branch:** General-None-FDA-reports  
**Compatibility:** Python 3.8+, Visual Studio 2022  

## 🎯 What's New

### ✨ Major Features
- **🔄 Complete FDA Removal**: All FDA-specific terminology, fields, and requirements have been removed
- **📁 Enhanced File Path Reporting**: Dedicated file path column with smart truncation and hover tooltips
- **🎨 Improved Table Layout**: Better text wrapping, column sizing, and professional appearance
- **🏢 General Purpose Design**: Suitable for any organization using Parasoft C/C++test

### 🔧 Technical Improvements
- **📊 Smart Path Display**: Long file paths automatically truncated to `...filename/folder` format
- **🖥️ Visual Studio 2022**: Full compatibility with Python project files and debugging
- **🐍 Virtual Environment**: Included requirements.txt and setup for isolated Python environment
- **💻 Cross-Platform**: Works on Windows, Linux, and macOS

### 🎨 UI/UX Enhancements
- **📋 Professional Tables**: Fixed column layouts with proper text alignment
- **🔤 Monospace Fonts**: File paths displayed in Courier New for better readability
- **📏 Responsive Design**: Tables adapt to content with minimum/maximum width constraints
- **🔍 Hover Tooltips**: Full file paths shown on hover for truncated displays

## 📋 Key Changes from FDA Version

| Feature | FDA Version | General Version |
|---------|------------|-----------------|
| **Fields** | Device Name, FDA Report Number | Software/Project Name, Report Number |
| **Documentation** | FDA compliance focused | General quality assurance |
| **Branding** | FDA-specific headers | Customizable organization branding |
| **Standards** | FDA validation requirements | Industry-standard static analysis |
| **File Paths** | Basic display | Enhanced with truncation and tooltips |

## 🏗️ Installation & Setup

### Prerequisites
- Python 3.8 or higher
- Visual Studio 2022 (optional, for development)
- Git (for cloning)

### Quick Start
1. **Clone the branch:**
   ```bash
   git clone -b General-None-FDA-reports https://github.com/zuwasi/FDA_Report_app.git
   cd FDA_Report_app
   ```

2. **Setup virtual environment:**
   ```bash
   python -m venv env
   env\Scripts\activate  # Windows
   # source env/bin/activate  # Linux/Mac
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python General_Parasoft_Report.py
   # OR double-click run_app.bat
   ```

### Visual Studio 2022
1. Open `General_Parasoft_Report.sln`
2. Ensure Python environment is configured
3. Press F5 to run with debugging

## 📊 Report Features

### Input Files Supported
- ✅ Parasoft C/C++test XML reports
- ✅ Parasoft C/C++test HTML reports  
- ✅ Parasoft .suppress files
- ✅ Local and GitHub repositories (for code metrics)

### Output Generated
- 📄 Professional HTML reports with CSS styling
- 📈 Historical progress charts (PNG)
- 📊 Code metrics and violation statistics
- 📁 Complete file path traceability

### Report Sections
1. **Software/Project Information**
2. **Source Code Metrics** (optional)
3. **Analysis Summary** (by severity)
4. **Historical Progress Charts**
5. **Violation Details** (with file paths)
6. **Suppression Details** (with justifications)
7. **Active Rules Documentation**

## 🔍 File Path Enhancements

### Before (v1.1.5)
```
| Severity | Line | Message | Rule |
| High | 42 | C:\Very\Long\Path\...\main.cpp: Memory leak | RULE_123 |
```

### After (v2.0.1)
```
| Severity | File Path | Line | Message | Rule |
| High | .../src/main.cpp | 42 | Memory leak | RULE_123 |
```

### Features
- **Smart Truncation**: `C:\Very\Long\Path\To\Project\src\main.cpp` → `.../src/main.cpp`
- **Hover Tooltips**: Full path shown on mouse hover
- **Monospace Font**: Consistent character spacing for paths
- **Proper Wrapping**: Long paths wrap correctly without overflow

## 📁 Project Structure

```
General-Parasoft-Report/
├── General_Parasoft_Report.py      # Main application
├── General_Parasoft_Report.pyproj  # VS2022 project file  
├── General_Parasoft_Report.sln     # VS2022 solution file
├── requirements.txt                # Python dependencies
├── run_app.bat                     # Easy execution script
├── README.md                       # Full documentation
├── CHANGELOG.md                    # Version history
├── .gitignore                      # Git ignore rules
└── env/                           # Virtual environment (after setup)
```

## 🚀 Usage Examples

### Basic Report Generation
1. Launch application
2. Select Parasoft XML/HTML report
3. Select suppression file (optional)
4. Enter software information
5. Choose output directory
6. Generate professional HTML report

### Advanced Features
- **Historical Tracking**: Add previous reports for trend analysis
- **Code Metrics**: Include repository analysis (GitHub or local)
- **Custom Branding**: Add company logo and information
- **Automated Workflow**: Use command-line arguments for CI/CD

## 🔧 Technical Specifications

### Python Dependencies
```
lxml>=4.6.0          # XML parsing
matplotlib>=3.5.0    # Chart generation  
pillow>=8.3.0        # Image processing
beautifulsoup4>=4.10.0  # HTML parsing
requests>=2.25.0     # GitHub API (optional)
pyinstaller>=4.0     # Executable creation (optional)
```

### System Requirements
- **Memory**: 512MB RAM minimum
- **Storage**: 100MB available space
- **Network**: Optional (for GitHub repository analysis)
- **Display**: 1024x768 minimum resolution

## 🐛 Bug Fixes

### Resolved Issues
- ✅ **File Path Text Overlap**: Fixed CSS styling for proper text display
- ✅ **Visual Studio Build**: Corrected project file XML syntax
- ✅ **Long Path Display**: Implemented smart truncation algorithm
- ✅ **Module Dependencies**: Added virtual environment support
- ✅ **Table Layout**: Fixed column width and text wrapping issues

## 🔮 Future Enhancements

### Planned Features (v2.1.0)
- 🔄 Command-line interface for automation
- 📊 Additional chart types and statistics
- 🎨 Customizable report templates
- 🔗 Integration with popular IDEs
- 📱 Responsive web report design

## 📞 Support & Contribution

### Getting Help
- 📖 Read the [README.md](README.md) for detailed instructions
- 📋 Check [CHANGELOG.md](CHANGELOG.md) for version history
- 🐛 Report issues on GitHub Issues
- 💡 Request features via GitHub Discussions

### Contributing
- 🍴 Fork the repository
- 🌿 Create feature branch from `General-None-FDA-reports`
- 📝 Make your changes with tests
- 📤 Submit pull request with detailed description

## 📜 License & Credits

**License:** MIT License (same as original)  
**Original Author:** zuwasi  
**General Edition:** Enhanced for universal use  
**Parasoft Integration:** Compatible with C/C++test 2024.x  

---

**🎉 Ready to generate professional static analysis reports for any organization!**

Download: [GitHub Repository](https://github.com/zuwasi/FDA_Report_app/tree/General-None-FDA-reports)
