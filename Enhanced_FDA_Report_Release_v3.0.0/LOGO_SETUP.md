# Logo Setup Instructions

## Adding Company Logos to Welcome Screen

The Enhanced FDA Report App supports displaying actual company logos on the welcome screen.

### Required Logo Files:

The application automatically loads logos from: **`C:\Parasoft\logos\`**

1. **`ESL.png`** - ESL company logo
   - Location: `C:\Parasoft\logos\ESL.png`
   - Recommended size: 120 x 80 pixels
   - Format: PNG with transparent background preferred
   
2. **`Parasoft Logo.png`** - Parasoft company logo  
   - Location: `C:\Parasoft\logos\Parasoft Logo.png`
   - Recommended size: 120 x 80 pixels
   - Format: PNG with transparent background preferred

### Automatic Detection:

- If logo files are present, they will be automatically loaded and displayed
- If logo files are missing, styled placeholder boxes will be shown instead
- The application gracefully handles missing files or image loading errors

### Logo Requirements:

- **File Format**: PNG format recommended (JPG also supported)
- **Size**: Images will be automatically resized to 120x80 pixels
- **Location**: Must be in `C:\Parasoft\logos\` directory
- **Naming**: Exact filenames required (case-sensitive): `ESL.png` and `Parasoft Logo.png`

### Fallback Behavior:

If logo files are not found or cannot be loaded:
- ESL logo area shows: Blue placeholder box with "ESL LOGO" text
- Parasoft logo area shows: Green placeholder box with "PARASOFT LOGO" text
- Application continues to function normally

### Dependencies:

Logo loading requires the PIL (Pillow) library:
```bash
pip install pillow
```

If PIL is not available, the application will use text placeholders instead.
