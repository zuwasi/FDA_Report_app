# Build Instructions for Enhanced FDA Report App

## Prerequisites

1. **Python 3.8 or higher** installed on your system
2. **Visual Studio 2022** with Python Tools for Visual Studio (optional, for VS development)
3. **pip** package manager

## Setup Instructions

### Option 1: Quick Setup (Recommended)

1. Run the setup script:
   ```bash
   install_requirements.bat
   ```

### Option 2: Manual Setup

1. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

### From Python

```bash
python Enhanced_FDA_Report_app.py
```

### From Visual Studio 2022

1. Open `Enhanced_FDA_Report_app.sln` in Visual Studio 2022
2. Set `Enhanced_FDA_Report_app.py` as the startup file
3. Press **F5** to run or **Ctrl+F5** to run without debugging

## Building Executable

### Option 1: Quick Build (Recommended)

Run the build script:
```batch
build_exe.bat
```

The executable will be created in the `dist/` directory.

### Option 2: Manual Build using PyInstaller

1. Install PyInstaller (if not already installed):
   ```bash
   pip install pyinstaller
   ```

2. Build the executable:
   ```bash
   pyinstaller --onefile --windowed --name "Enhanced_FDA_Report_app" Enhanced_FDA_Report_app.py
   ```

### Option 3: Build from Visual Studio

1. Open the solution in Visual Studio 2022
2. Set configuration to **Release**
3. Go to **Build** → **Build Solution** (or press **Ctrl+Shift+B**)
4. The executable will be built automatically using the AfterBuild target

## Build Output

After successful build, you'll find:
- `Enhanced_FDA_Report_app.exe` in the `dist/` directory
- This is a standalone executable that can be distributed without Python installation

## Troubleshooting

### Common Issues

1. **Missing Dependencies**: Run `install_requirements.bat` to ensure all packages are installed
2. **PyInstaller Not Found**: Install using `pip install pyinstaller`
3. **Build Fails**: Check that all Python packages are properly installed and compatible
4. **Executable Won't Run**: Ensure all dependencies are included in the PyInstaller spec file

### Visual Studio Issues

1. **Python Tools Not Found**: Install Python Tools for Visual Studio 2022
2. **Project Won't Load**: Ensure you have the correct Python environment configured
3. **Debug Issues**: Check that the correct Python interpreter is selected

## Distribution

The built executable (`Enhanced_FDA_Report_app.exe`) is self-contained and can be distributed to users without requiring Python installation on their machines.

## Development Notes

- The project uses PyInstaller to create standalone executables
- All GUI dialogs are designed to work in windowed mode (no console)
- Dependencies are automatically bundled with the executable
- The app creates temporary directories for processing that are cleaned up automatically
