# Changelog - General Parasoft Report Viewer

## Version 2.0.1 - Enhanced File Path Reporting

### New Features
- **Complete File Paths**: Added dedicated "File Path" column to violation and suppression tables
- **Path Normalization**: Automatically converts relative paths to absolute paths when possible
- **Enhanced Table Layout**: Improved table styling with fixed column widths for better readability
- **Hover Tooltips**: File path cells show full path on hover for long paths

### Visual Improvements
- **Monospace Font**: File paths displayed in monospace font for better readability
- **Responsive Columns**: 
  - File Path: 30% width
  - Line: 8% width  
  - Message: 45% width
  - Rule: 17% width
- **Word Breaking**: Long file paths break appropriately to prevent table overflow

### Technical Changes
- **Data Structure**: Modified violation data to store file paths separately from messages
- **Backward Compatibility**: Maintains compatibility with existing report data formats
- **Path Resolution**: Added `_normalize_file_path()` function to resolve relative paths

### Files Modified
- `General_Parasoft_Report.py` - Main application with enhanced file path handling
- Added CSS styling for improved file path display
- Updated HTML generation to include separate file path column

### Benefits
- **Better Debugging**: Developers can easily locate source files with violations
- **Improved Navigation**: Complete paths help with IDE navigation and file location
- **Professional Reporting**: Enhanced table layout provides clearer information presentation
- **Tool Integration**: Easier integration with other development tools that need file paths

## Version 2.0.0 - General Edition
- Removed FDA-specific references
- Generalized for any organization use
- Added Visual Studio 2022 support
- Enhanced documentation

## Version 1.1.5 - Original FDA Version
- Initial FDA-specific implementation
