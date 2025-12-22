# Python 2 Setup Guide for PDF Analysis

## Why Python 2 is Needed

This malware analysis project uses **peepdf** for advanced PDF analysis, which requires **Python 2.7**. While the main application runs on Python 3, peepdf is a legacy tool that only works with Python 2.

## Quick Setup

### Option 1: Install Python 2.7 (Recommended)

#### Windows Installation

1. **Download Python 2.7.18** (final version):
   - Visit: https://www.python.org/downloads/release/python-2718/
   - Download: `Windows x86-64 MSI installer` for 64-bit systems
   - Or download: `Windows x86 MSI installer` for 32-bit systems

2. **Install Python 2.7**:
   - Run the installer
   - **IMPORTANT**: Check "Add python.exe to PATH" during installation
   - Recommended install location: `C:\Python27\`

3. **Verify Installation**:
   ```powershell
   python2 --version
   # Should show: Python 2.7.18
   ```

4. **If `python2` command not found**:
   - The installer adds `python.exe` but not `python2.exe`
   - Create a copy or symbolic link:
   ```powershell
   # Option A: Copy the executable (simple)
   copy C:\Python27\python.exe C:\Python27\python2.exe
   
   # Option B: Use full path in environment variable (see below)
   ```

### Option 2: Configure Custom Python 2 Path

If Python 2 is installed in a non-standard location or not in PATH:

#### Set Environment Variable (Windows)

**Temporary (current PowerShell session only)**:
```powershell
$env:PYTHON2_PATH = "C:\Python27\python.exe"
```

**Permanent (User level)**:
```powershell
[System.Environment]::SetEnvironmentVariable('PYTHON2_PATH', 'C:\Python27\python.exe', 'User')
```

**Permanent (System level - requires admin)**:
```powershell
[System.Environment]::SetEnvironmentVariable('PYTHON2_PATH', 'C:\Python27\python.exe', 'Machine')
```

**Or use System Properties (GUI)**:
1. Right-click "This PC" → Properties → Advanced system settings
2. Click "Environment Variables"
3. Under "User variables" or "System variables", click "New"
4. Variable name: `PYTHON2_PATH`
5. Variable value: `C:\Python27\python.exe` (adjust to your path)
6. Click OK and restart any open terminals

### Option 3: Modify the Code Directly

If you prefer not to use environment variables:

Edit `backend\utils\pdf_analyzer.py` line 28:

```python
# Change from:
PYTHON2_PATH = 'python2'

# To your Python 2 installation path:
PYTHON2_PATH = r'C:\Python27\python.exe'
```

## Testing Your Setup

After installation, test that everything works:

```powershell
# Test Python 2 is accessible
python2 --version

# Or test with full path
C:\Python27\python.exe --version

# Test peepdf directly
python2 External\peepdf\peepdf.py --help
```

## Troubleshooting

### Error: `'python2' is not recognized`

**Problem**: Python 2 is installed but not accessible via `python2` command.

**Solutions**:
1. Use Option 2 above to set `PYTHON2_PATH` environment variable
2. Create `python2.exe` copy: `copy C:\Python27\python.exe C:\Python27\python2.exe`
3. Add Python 2 to PATH manually in System Environment Variables

### Error: `peepdf not found`

**Problem**: peepdf script is missing from `External\peepdf\` folder.

**Solution**: Ensure `peepdf.py` exists at: `External\peepdf\peepdf.py`

### Error: `No module named 'X'` when running peepdf

**Problem**: Python 2 is missing required dependencies.

**Solution**: Install peepdf dependencies using pip for Python 2:
```powershell
# Install pip for Python 2 first (if needed)
python2 -m ensurepip

# Install peepdf dependencies
python2 -m pip install colorama
python2 -m pip install pylzma
```

### Security Note

Python 2.7 reached end-of-life in January 2020 and no longer receives security updates. It is only used in this project for the isolated peepdf analysis tool. Consider running the analysis in a sandboxed or isolated environment for production use.

### Alternative: Skip peepdf Analysis

If you cannot or prefer not to install Python 2:

- The PDF analysis will continue to work with other tools (YARA, PDFiD)
- Only peepdf-specific analysis will be skipped
- The application will show a warning but continue functioning
- You'll miss some advanced PDF structure analysis features

## Verification Checklist

- [ ] Python 2.7 installed
- [ ] `python2 --version` works in terminal (or `PYTHON2_PATH` is set)
- [ ] peepdf.py exists in `External\peepdf\` folder
- [ ] Test command runs without errors: `python2 External\peepdf\peepdf.py --help`
- [ ] Backend application starts without Python 2 errors

## Need Help?

If you encounter issues:
1. Check that Python 2.7.18 is installed (not Python 2.6 or earlier)
2. Verify PATH or PYTHON2_PATH environment variable is set correctly
3. Restart your terminal/PowerShell after setting environment variables
4. Ensure peepdf script and dependencies are present
