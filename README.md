# PowerShell GUI Utility Script

A diagnostic PowerShell script designed to **systematically test and troubleshoot common issues with GUI form creation** in Windows PowerShell. This script performs step-by-step checks—ranging from environment setup to form rendering—helping you pinpoint exactly where GUI problems may occur. It’s perfect for newcomers and advanced users who want to ensure their environment is ready for GUI-based scripting.

## Features

- **Checks PowerShell and CLR Versions:**
Prints your current PowerShell and .NET/CLR runtime details.
- **Assembly Loading Tests:**
Verifies that essential assemblies (`System.Windows.Forms`, `System.Drawing`) are loadable, with clear error messages if not.
- **Display Environment Check:**
Detects all attached screens and prints their resolutions to confirm access to a display.
- **Form Creation Diagnostics:**
Tests if a basic WinForms Form can be instantiated. Outputs object creation status and form properties.
- **MessageBox Test:**
Shows a simple message box to confirm minimal GUI functionality.
- **Form Display Test:**
Attempts to display a basic form using both `ShowDialog()` and a fallback to `Show()` with `Application.DoEvents()`, including a close button and test label.
- **Detects Common Issues:**
    - Warns if running in PowerShell ISE (which often causes GUI failures).
    - Checks execution policy and warns if set to `Restricted`.
    - Checks session type and flags desktop-unfriendly contexts (like "Services").
- **Guidance for Next Steps:**
If all diagnostics pass but your main script still fails, the script suggests focusing on more complex event handling issues.


## Usage

1. **Copy the script contents into a `.ps1` file.**
2. **Run in a regular PowerShell console**
_Do not run in PowerShell ISE, as it can prevent GUIs from displaying!_
3. Watch the **step-by-step output** in the console.
    - Each test will print results in color (when supported).
    - Warnings are unambiguous and actionable.
4. Use the diagnostic output to resolve configuration issues (e.g., install missing assemblies, run in a compatible shell, adjust execution policy).

## Example Output

```
=== PowerShell GUI Diagnostics ===
Testing GUI capabilities step by step...

1. Testing PowerShell Environment:
PowerShell Version: 5.1.19041.3031
CLR Version: 4.0.30319.42000
OS: Microsoft Windows 10.0.19045

2. Testing Assembly Loading:
✓ System.Windows.Forms loaded successfully
✓ System.Drawing loaded successfully

3. Testing Display Environment:
Number of screens detected: 2
Screen: \\.\DISPLAY1 - Resolution: 1920x1080
Screen: \\.\DISPLAY2 - Resolution: 1280x1024

...
```


## Troubleshooting

- **If you see a warning about PowerShell ISE**, re-run the script in a regular PowerShell console.
- **If assemblies fail to load**, ensure you’re running a compatible version of Windows and PowerShell (requires Windows PowerShell—not PowerShell Core/7+ for full WinForms compatibility).
- **If the form does not appear**, check your session type and ensure you're not running in a non-interactive session (like Services).
- **If execution policy is restrictive**, set it (temporarily) to something less strict with `Set-ExecutionPolicy RemoteSigned -Scope Process`.


## When All Tests Pass But Main Script Fails

If every test in this diagnostic passes but your main script’s GUI still does not display or work, **the problem is likely in the complexity of your custom form design or event handling code**. This tool verifies the baseline—the foundation your advanced GUIs need to function.

## License

Feel free to modify and distribute.
Attribution/credit appreciated.

