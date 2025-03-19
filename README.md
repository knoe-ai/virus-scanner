# Advanced Virus Scanner

A comprehensive file analysis tool that combines multiple scanning approaches to detect potential security threats in files, directories, and archives.

## Features

- 🔍 Multiple scanning capabilities:
  - Built-in virus signature detection
  - Malware pattern recognition
  - Harmful code analysis in scripts
  - Cryptocurrency mining detection
  - ClamAV integration
  - YARA Rules support
  - National Vulnerability Database (NVD) integration

- 📁 Supports various file types:
  - Executables (.exe, .dll, .sys)
  - Scripts (.py, .js, .php, .bat)
  - Documents with macros (.docm, .xlsm)
  - Archives (.zip, .rar, .7z)
  - General files (text, images, media)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/virus-scanner.git
cd virus-scanner
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Optional: Install ClamAV

For Windows:
```bash
# Download and install ClamAV from https://www.clamav.net/downloads
```

For Linux:
```bash
sudo apt-get install clamav clamav-daemon
sudo systemctl start clamav-daemon
```

For macOS:
```bash
brew install clamav
```

## Usage

Basic usage:
```bash
python virus_scan.py [target] --os [operating_system]
```

Examples:
```bash
# Scan a single file
python virus_scan.py suspicious_file.exe --os win

# Scan a directory
python virus_scan.py /path/to/directory --os linux --debug

# Scan a zip archive
python virus_scan.py archive.zip --os mac

# Use only ClamAV
python virus_scan.py file.exe --os win --clamav-only

# Display help information
python virus_scan.py --readme
```

### Command Line Arguments

- `target`: File, directory, or zip archive to scan
- `--os`: Target operating system (win, mac, linux, android)
- `--debug`: Enable debug logging
- `--clamav-only`: Use only ClamAV for scanning
- `--readme`: Display detailed program information

## Enhanced Features

### Code Analysis
- Line and column numbers for detected issues
- Code snippets showing concerns
- Detailed explanations of potential threats
- Google search links for additional information

### Zip File Handling
- Safe extraction of compressed files
- Handles problematic file names
- Temporary directory management
- Recursive scanning of contents

### Multiple Integration Options
- YARA Rules for custom pattern matching
- NVD for known vulnerability checking
- ClamAV for traditional antivirus scanning

## Log Files

The scanner creates two types of log files:

1. Debug Log (debug_YYYYMMDD_HHMMSS.log):
   - Created with --debug flag
   - Contains detailed scanning process information

2. Scan Results Log (virus_scan_YYYYMMDD_HHMMSS.log):
   - Created upon request after scan completion
   - Contains comprehensive scan results

## Risk Categories

- HIGH: Critical security threats requiring immediate attention
- MEDIUM: Potential security risks that should be reviewed
- LOW: Minor concerns or informational findings

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Best Practices

1. Always use the --debug flag when investigating issues
2. Create log files for important scans
3. Use appropriate OS flag for accurate detection
4. Review all HIGH and MEDIUM risk findings
5. Keep ClamAV updated if using ClamAV integration
6. Regularly update YARA rules

## Disclaimer

This tool is designed for security analysis and should be used responsibly. Some detected patterns may be legitimate in certain contexts - always review findings and use professional judgment. 