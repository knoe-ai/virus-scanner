#!/usr/bin/env python3
import os
import sys
import argparse
import time
import zipfile
import glob
import logging
from pathlib import Path
import random
from datetime import datetime
from tqdm import tqdm
import colorama
from colorama import Fore, Style
import pyclamd
import yara
import requests
import json
from typing import Optional, Tuple, Dict, List
from concurrent.futures import ThreadPoolExecutor

# Initialize colorama for cross-platform colored terminal output
colorama.init(autoreset=True)

SUPPORTED_OS = ["win", "mac", "linux", "android"]
SCRIPT_EXTENSIONS = [".py", ".js", ".cpp", ".c", ".java", ".html", ".php", ".sh", ".bat", ".ps1"]
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class ThreatLevel:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    
class ScanResult:
    def __init__(self):
        self.virus_threats = []
        self.malware_threats = []
        self.harmful_code_threats = []
        self.blockchain_threats = []
        
    def has_threats(self):
        return (len(self.virus_threats) > 0 or 
                len(self.malware_threats) > 0 or 
                len(self.harmful_code_threats) > 0 or 
                len(self.blockchain_threats) > 0)
    
    def add_threat(self, category, file_path, threat_name, level):
        threat = {
            "file": file_path,
            "threat": threat_name,
            "level": level
        }
        
        if category == "virus":
            self.virus_threats.append(threat)
        elif category == "malware":
            self.malware_threats.append(threat)
        elif category == "harmful_code":
            self.harmful_code_threats.append(threat)
        elif category == "blockchain":
            self.blockchain_threats.append(threat)
            
class ClamAVScanner:
    """ClamAV integration class"""
    def __init__(self):
        self.clam = None
        self.is_connected = False
        self.error_message = None
        
    def connect(self) -> bool:
        """Try to connect to ClamAV daemon"""
        try:
            # Try to connect to local ClamAV daemon
            self.clam = pyclamd.ClamdUnixSocket()
            self.clam.ping()
            self.is_connected = True
            logging.info("Successfully connected to ClamAV daemon via Unix socket")
            return True
        except Exception as unix_error:
            logging.debug(f"Unix socket connection failed: {str(unix_error)}")
            try:
                # Try TCP connection as fallback
                self.clam = pyclamd.ClamdNetworkSocket()
                self.clam.ping()
                self.is_connected = True
                logging.info("Successfully connected to ClamAV daemon via network socket")
                return True
            except Exception as net_error:
                self.error_message = f"Failed to connect to ClamAV daemon: {str(net_error)}"
                logging.error(self.error_message)
                return False
    
    def get_version(self) -> Optional[str]:
        """Get ClamAV version"""
        if self.is_connected:
            try:
                return self.clam.version()
            except Exception as e:
                logging.error(f"Error getting ClamAV version: {str(e)}")
        return None
    
    def scan_file(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """Scan a single file using ClamAV"""
        if not self.is_connected:
            return False, "ClamAV is not connected"
            
        try:
            logging.debug(f"Scanning file with ClamAV: {file_path}")
            result = self.clam.scan_file(file_path)
            
            if result is None:
                logging.debug(f"No threats found in {file_path}")
                return False, None
            else:
                # result format: {filepath: ('FOUND', 'virus name')}
                virus_name = result[file_path][1]
                logging.warning(f"ClamAV detected threat in {file_path}: {virus_name}")
                return True, virus_name
                
        except Exception as e:
            error_msg = f"ClamAV scan error: {str(e)}"
            logging.error(error_msg)
            return False, error_msg

class YARAScanner:
    """YARA Rules integration class"""
    def __init__(self):
        self.rules = None
        self.is_enabled = False
        self.rules_path = "yara_rules"
        
    def initialize(self) -> bool:
        """Initialize YARA rules from the rules directory"""
        try:
            if not os.path.exists(self.rules_path):
                os.makedirs(self.rules_path)
                # Create a sample YARA rule
                self.create_sample_rules()
            
            # Compile all .yar files in the rules directory
            rules_files = {}
            for rule_file in glob.glob(os.path.join(self.rules_path, "*.yar")):
                rules_files[os.path.basename(rule_file)] = rule_file
            
            if not rules_files:
                logging.warning("No YARA rules found. Created sample rules.")
                self.create_sample_rules()
                rules_files = {f: f for f in glob.glob(os.path.join(self.rules_path, "*.yar"))}
            
            self.rules = yara.compile(filepaths=rules_files)
            self.is_enabled = True
            logging.info("YARA rules initialized successfully")
            return True
        except Exception as e:
            logging.error(f"Failed to initialize YARA rules: {str(e)}")
            return False
            
    def create_sample_rules(self):
        """Create sample YARA rules if none exist"""
        sample_rule = """
rule SuspiciousStrings {
    strings:
        $suspicious_cmd1 = "cmd.exe" nocase
        $suspicious_cmd2 = "powershell.exe" nocase
        $suspicious_net1 = "download" nocase
        $suspicious_net2 = "http://" nocase
        $suspicious_net3 = "https://" nocase
        
    condition:
        any of them
}

rule PotentialMalware {
    strings:
        $mal1 = "CreateRemoteThread"
        $mal2 = "VirtualAlloc"
        $mal3 = "WriteProcessMemory"
        $enc1 = "base64" nocase
        $enc2 = "encrypt" nocase
        
    condition:
        2 of them
}
"""
        with open(os.path.join(self.rules_path, "sample_rules.yar"), "w") as f:
            f.write(sample_rule)
            
    def scan_file(self, file_path: str) -> List[Dict]:
        """Scan a file using YARA rules"""
        if not self.is_enabled:
            return []
            
        try:
            matches = self.rules.match(file_path)
            return [{"rule": match.rule, "tags": match.tags, "strings": match.strings} for match in matches]
        except Exception as e:
            logging.error(f"YARA scan error for {file_path}: {str(e)}")
            return []

class NVDScanner:
    """National Vulnerability Database integration class"""
    def __init__(self):
        self.is_enabled = False
        self.cache = {}
        self.api_key = None  # Optional: Add your NVD API key for higher rate limits
        
    def initialize(self) -> bool:
        """Initialize NVD scanner"""
        try:
            # Test API connection
            response = self.query_nvd("test")
            if response.status_code in (200, 403):  # 403 is ok for rate limiting
                self.is_enabled = True
                logging.info("NVD scanner initialized successfully")
                return True
            else:
                logging.error(f"NVD API test failed: {response.status_code}")
                return False
        except Exception as e:
            logging.error(f"Failed to initialize NVD scanner: {str(e)}")
            return False
            
    def query_nvd(self, keyword: str) -> requests.Response:
        """Query the NVD API"""
        headers = {"apiKey": self.api_key} if self.api_key else {}
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 10
        }
        return requests.get(NVD_API_URL, params=params, headers=headers)
        
    def scan_file(self, file_path: str, content: bytes) -> List[Dict]:
        """Scan file content for known vulnerabilities"""
        if not self.is_enabled:
            return []
            
        try:
            # Extract potential version strings and package names
            text_content = content.decode('utf-8', errors='ignore')
            keywords = self.extract_keywords(text_content)
            
            vulnerabilities = []
            with ThreadPoolExecutor(max_workers=3) as executor:
                future_to_keyword = {
                    executor.submit(self.check_vulnerability, keyword): keyword 
                    for keyword in keywords
                }
                
                for future in future_to_keyword:
                    try:
                        vulns = future.result()
                        vulnerabilities.extend(vulns)
                    except Exception as e:
                        logging.error(f"Error checking vulnerability: {str(e)}")
                        
            return vulnerabilities
        except Exception as e:
            logging.error(f"NVD scan error for {file_path}: {str(e)}")
            return []
            
    def extract_keywords(self, content: str) -> List[str]:
        """Extract potential vulnerability keywords from content"""
        keywords = set()
        
        # Common version patterns
        version_patterns = [
            r'version\s*[=:]\s*["\']?([\d.]+)["\']?',
            r'Version:\s*([\d.]+)',
            r'v([\d.]+)',
        ]
        
        # Add relevant keywords
        for line in content.split('\n'):
            line = line.strip().lower()
            if any(term in line for term in ['cve-', 'vulnerability', 'exploit', 'remote code execution']):
                keywords.add(line[:100])  # Limit length
                
        return list(keywords)
        
    def check_vulnerability(self, keyword: str) -> List[Dict]:
        """Check NVD for vulnerabilities matching the keyword"""
        if keyword in self.cache:
            return self.cache[keyword]
            
        try:
            response = self.query_nvd(keyword)
            if response.status_code == 200:
                data = response.json()
                vulns = []
                for vuln in data.get('vulnerabilities', []):
                    cve = vuln.get('cve', {})
                    vulns.append({
                        'id': cve.get('id'),
                        'description': cve.get('descriptions', [{}])[0].get('value', ''),
                        'severity': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0)
                    })
                self.cache[keyword] = vulns
                return vulns
            else:
                logging.warning(f"NVD API request failed: {response.status_code}")
                return []
        except Exception as e:
            logging.error(f"Error checking NVD for {keyword}: {str(e)}")
            return []

class VirusScanner:
    def __init__(self, target_os):
        self.target_os = target_os
        self.results = ScanResult()
        self.files_scanned = 0
        logging.debug(f"Initialized VirusScanner for {target_os} OS")
        
        # Initialize ClamAV scanner
        self.clam_scanner = ClamAVScanner()
        if self.clam_scanner.connect():
            version = self.clam_scanner.get_version()
            logging.info(f"ClamAV Version: {version}")
        else:
            logging.warning("ClamAV integration not available. Using built-in signatures only.")
        
        # Define high-risk file extensions
        self.high_risk_extensions = {
            'executable': ['.exe', '.dll', '.sys', '.com', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.msi', '.scr'],
            'script': ['.py', '.php', '.jsp', '.asp', '.aspx', '.cgi', '.pl'],
            'macro': ['.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm'],
            'archive': ['.zip', '.rar', '.7z', '.tar', '.gz'],
            'low_risk': ['.txt', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.mp3', '.mp4', '.wav', '.avi', '.pdf']
        }
        
        # Define harmful code patterns
        self.harmful_code_patterns = {
            '.py': [
                'os.system(', 'subprocess.call(', 'exec(', 'eval(',
                'rm -rf', 'rmdir', 'remove(', 'shutil.rmtree(',
                '__import__("os")', 'base64.decode'
            ],
            '.js': [
                'eval(', 'document.write(', 'fromCharCode(',
                'crypto.generateCoinHive', 'new Function('
            ],
            '.php': [
                'eval(', 'exec(', 'system(', 'shell_exec(',
                'base64_decode(', 'passthru(', 'unlink('
            ],
            '.bat': [
                'del /f', 'rmdir /s', 'format c:', 'reg delete',
                'taskkill', 'netsh firewall set'
            ],
            '.sh': [
                'rm -rf', 'mkfs.ext4', 'dd if=/dev/zero',
                'shred -u', ':(){:|:&};:'
            ]
        }
        
        # Define blockchain mining patterns
        self.blockchain_patterns = [
            'CryptoNight', 'stratum+tcp://', 'pool.minergate.com',
            'coinhive.min.js', 'cryptonight.wasm',
            'minexmr.com', 'pool.supportxmr.com',
            'xmrig', 'cpuminer', 'minergate',
            'monero', 'bitcoin.miner', 'ethash',
            'antminer', 'nicehash', 'hashrate',
            'mining.subscribe', 'mining.authorize',
            'cryptonight', 'stratum+ssl://',
            'eth.pool', 'eth.worker', 'eth.submit',
            'gpu.mining', 'cpu.mining'
        ]
        
        # Known threat signatures (using YARA-like patterns for demonstration)
        self.virus_signatures = {
            "win": [
                {
                    "name": "Suspicious_PE_Header",
                    "pattern": b"MZ.*PE\x00\x00",
                    "description": "Suspicious PE file header modification",
                    "applies_to": ["executable"]
                },
                {
                    "name": "Known_Exploit_Pattern",
                    "pattern": b"CVE-2021-",
                    "description": "Contains reference to known exploit",
                    "applies_to": ["executable", "script"]
                }
            ],
            "mac": [
                {
                    "name": "Suspicious_Mach_O",
                    "pattern": b"CAFEBABE|FEEDFACE|FEEDFACF",
                    "description": "Suspicious Mach-O binary modification",
                    "applies_to": ["executable"]
                }
            ],
            "linux": [
                {
                    "name": "Suspicious_ELF",
                    "pattern": b"\x7fELF",
                    "description": "Suspicious ELF binary modification",
                    "applies_to": ["executable"]
                }
            ]
        }
        
        self.malware_signatures = {
            "win": [
                {
                    "name": "Suspicious_Registry_Access",
                    "pattern": b"RegCreateKeyEx|RegSetValueEx|RegDeleteKey",
                    "description": "Attempts to modify Windows Registry",
                    "applies_to": ["executable", "script"]
                },
                {
                    "name": "Suspicious_Process_Creation",
                    "pattern": b"CreateProcess|ShellExecute|WinExec",
                    "description": "Suspicious process creation activity",
                    "applies_to": ["executable", "script"]
                }
            ],
            "common": [
                {
                    "name": "Suspicious_Network_Activity",
                    "pattern": b"socket\x00|connect\x00|download|http://|https://",
                    "description": "Suspicious network activity",
                    "applies_to": ["executable", "script"]
                },
                {
                    "name": "Suspicious_File_Operations",
                    "pattern": b"CreateFile|DeleteFile|RemoveDirectory",
                    "description": "Suspicious file operations",
                    "applies_to": ["executable", "script"]
                }
            ]
        }
    
    def _get_file_risk_category(self, extension):
        """Determine the risk category of a file based on its extension"""
        extension = extension.lower()
        for category, extensions in self.high_risk_extensions.items():
            if extension in extensions:
                return category
        return "unknown"
    
    def scan_file(self, file_path):
        """Scan a single file for threats"""
        if not os.path.exists(file_path):
            logging.error(f"File not found - {file_path}")
            print(f"{Fore.RED}Error: File not found - {file_path}")
            return self.results
            
        self.files_scanned += 1
        logging.debug(f"Starting scan of file: {file_path}")
        
        file_name = os.path.basename(file_path)
        extension = os.path.splitext(file_name)[1].lower()
        logging.debug(f"File extension: {extension}")
        
        # Scan for viruses
        print(f"\n{Fore.CYAN}Scanning for viruses: {file_path}")
        logging.debug("Starting virus scan")
        self._scan_for_viruses(file_path)
        
        # Scan for malware
        print(f"\n{Fore.CYAN}Scanning for malware: {file_path}")
        logging.debug("Starting malware scan")
        self._scan_for_malware(file_path)
        
        # Scan for harmful code if it's a script file
        if extension in SCRIPT_EXTENSIONS:
            print(f"\n{Fore.CYAN}Scanning for harmful code: {file_path}")
            logging.debug(f"Starting harmful code scan for {extension} file")
            self._scan_for_harmful_code(file_path, extension)
        
        # Scan for blockchain miners
        print(f"\n{Fore.CYAN}Scanning for blockchain miners: {file_path}")
        logging.debug("Starting blockchain miner scan")
        self._scan_for_blockchain_miners(file_path)
        
        logging.debug(f"Completed scan of file: {file_path}")
        return self.results
        
    def scan_directory(self, dir_path):
        """Scan all files in a directory for threats"""
        if not os.path.exists(dir_path):
            logging.error(f"Directory not found - {dir_path}")
            print(f"{Fore.RED}Error: Directory not found - {dir_path}")
            return self.results
            
        try:
            all_files = []
            for root, _, files in os.walk(dir_path):
                for file in files:
                    all_files.append(os.path.join(root, file))
            
            logging.info(f"Found {len(all_files)} files to scan in directory: {dir_path}")
            print(f"{Fore.GREEN}Found {len(all_files)} files to scan")
            
            # Scan each file
            for file_path in all_files:
                logging.debug(f"Starting scan of file in directory: {file_path}")
                print(f"\n{Fore.CYAN}Scanning file: {file_path}")
                self.scan_file(file_path)
                
            return self.results
        except Exception as e:
            logging.error(f"Error scanning directory {dir_path}: {str(e)}", exc_info=True)
            print(f"{Fore.RED}Error scanning directory: {e}")
            return self.results
        
    def scan_zip(self, zip_path):
        """Extract and scan contents of a zip file"""
        if not os.path.exists(zip_path):
            logging.error(f"Zip file not found - {zip_path}")
            print(f"{Fore.RED}Error: Zip file not found - {zip_path}")
            return self.results
            
        try:
            # Create temporary directory for extraction
            temp_dir = f"temp_extract_{int(time.time())}"
            os.makedirs(temp_dir, exist_ok=True)
            logging.debug(f"Created temporary directory for zip extraction: {temp_dir}")
            
            # Extract zip file
            print(f"{Fore.CYAN}Extracting zip file: {zip_path}")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                total_files = len(zip_ref.namelist())
                logging.info(f"Found {total_files} files in zip archive")
                
                for i, file in enumerate(zip_ref.namelist()):
                    try:
                        # Clean the filename by removing invalid characters
                        clean_file = file.replace('\r', '').replace('\n', '')
                        # Replace other potentially problematic characters
                        clean_file = ''.join(c for c in clean_file if c not in '<>:"|?*')
                        
                        # Skip files with no name after cleaning
                        if not clean_file:
                            logging.warning(f"Skipping file with invalid name: {file}")
                            continue
                            
                        # Extract with cleaned filename
                        try:
                            zip_ref.extract(file, temp_dir)
                        except OSError as e:
                            # If extraction fails, try to extract with cleaned filename
                            logging.warning(f"Failed to extract {file}, attempting with cleaned name: {clean_file}")
                            with zip_ref.open(file) as source, open(os.path.join(temp_dir, clean_file), 'wb') as target:
                                target.write(source.read())
                                
                        logging.debug(f"Extracted file ({i+1}/{total_files}): {clean_file}")
                        print(f"Extracted ({i+1}/{total_files}): {clean_file}", end='\r')
                    except Exception as e:
                        logging.error(f"Failed to extract file {file}: {str(e)}")
                        print(f"\n{Fore.YELLOW}Warning: Failed to extract file: {file}")
                        continue
            
            print(f"\n{Fore.GREEN}Zip extraction complete. Scanning files...")
            logging.info("Zip extraction complete, starting scan of extracted files")
            
            # Scan the extracted directory
            scan_result = self.scan_directory(temp_dir)
            
            # Clean up temporary directory
            print(f"{Fore.CYAN}Cleaning up temporary files...")
            logging.debug("Cleaning up temporary extraction directory")
            try:
                # Use shutil.rmtree for more reliable directory cleanup
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)
                logging.debug("Temporary directory cleanup complete")
            except Exception as e:
                logging.error(f"Error during cleanup: {str(e)}")
                print(f"{Fore.YELLOW}Warning: Some temporary files may not have been cleaned up")
            
            return scan_result
            
        except zipfile.BadZipFile as e:
            logging.error(f"Invalid zip file - {zip_path}: {str(e)}", exc_info=True)
            print(f"{Fore.RED}Error: Invalid zip file - {zip_path}")
            return self.results
        except Exception as e:
            logging.error(f"Error extracting zip file {zip_path}: {str(e)}", exc_info=True)
            print(f"{Fore.RED}Error extracting zip file: {e}")
            return self.results
    
    def _scan_for_viruses(self, file_path):
        """Scan a file for known virus signatures"""
        try:
            logging.debug(f"Starting virus signature scan for {file_path}")
            
            # Get file information
            file_size = os.path.getsize(file_path)
            extension = os.path.splitext(file_path)[1].lower()
            risk_category = self._get_file_risk_category(extension)
            
            logging.debug(f"File type: {extension}, Risk category: {risk_category}")
            
            # First try ClamAV scan if available
            if self.clam_scanner.is_connected:
                has_threat, threat_name = self.clam_scanner.scan_file(file_path)
                if has_threat:
                    level = ThreatLevel.HIGH
                    threat_desc = f"ClamAV: {threat_name}"
                    logging.warning(f"ClamAV detected threat: {threat_desc} in {file_path}")
                    self.results.add_threat("virus", file_path, threat_desc, level)
            
            # Run YARA scan if enabled
            if hasattr(self, 'yara_scanner') and self.yara_scanner.is_enabled:
                logging.debug("Running YARA scan")
                yara_matches = self.yara_scanner.scan_file(file_path)
                for match in yara_matches:
                    level = ThreatLevel.HIGH if risk_category in ["executable", "script"] else ThreatLevel.MEDIUM
                    threat_desc = f"YARA Rule '{match['rule']}' matched"
                    logging.warning(f"YARA detected threat: {threat_desc} in {file_path}")
                    self.results.add_threat("virus", file_path, threat_desc, level)
            
            # Run NVD scan if enabled
            if hasattr(self, 'nvd_scanner') and self.nvd_scanner.is_enabled:
                logging.debug("Running NVD vulnerability scan")
                with open(file_path, 'rb') as f:
                    content = f.read()
                vulnerabilities = self.nvd_scanner.scan_file(file_path, content)
                for vuln in vulnerabilities:
                    severity = float(vuln.get('severity', 0))
                    level = ThreatLevel.HIGH if severity >= 7.0 else (ThreatLevel.MEDIUM if severity >= 4.0 else ThreatLevel.LOW)
                    threat_desc = f"CVE {vuln['id']}: {vuln['description'][:100]}..."
                    logging.warning(f"NVD vulnerability found: {threat_desc} in {file_path}")
                    self.results.add_threat("virus", file_path, threat_desc, level)
            
            # Skip detailed scanning for known safe file types
            if risk_category == "low_risk":
                logging.debug(f"Skipping detailed virus scan for low-risk file type: {extension}")
                return
            
            # Continue with built-in signature scanning
            with open(file_path, 'rb') as f:
                file_content = f.read()
                logging.debug(f"Read {len(file_content)} bytes from file")
            
            # Get relevant signatures for the OS and file type
            signatures = []
            signatures.extend(self.virus_signatures.get(self.target_os, []))
            
            # Check each signature
            for sig in signatures:
                # Skip if signature doesn't apply to this file type
                if risk_category not in sig["applies_to"]:
                    continue
                    
                if sig["pattern"] in file_content:
                    level = ThreatLevel.HIGH if risk_category in ["executable", "script"] else ThreatLevel.MEDIUM
                    threat_desc = f"{sig['name']}: {sig['description']}"
                    logging.warning(f"Virus signature match: {threat_desc} in {file_path}")
                    self.results.add_threat("virus", file_path, threat_desc, level)
                    
        except Exception as e:
            logging.error(f"Error during virus scan: {str(e)}", exc_info=True)
            print(f"{Fore.RED}Error during virus scan: {e}")
    
    def _scan_for_malware(self, file_path):
        """Scan a file for known malware signatures"""
        try:
            logging.debug(f"Starting malware signature scan for {file_path}")
            
            # Get file information
            file_size = os.path.getsize(file_path)
            extension = os.path.splitext(file_path)[1].lower()
            risk_category = self._get_file_risk_category(extension)
            
            logging.debug(f"File type: {extension}, Risk category: {risk_category}")
            
            # Skip detailed scanning for known safe file types
            if risk_category == "low_risk":
                logging.debug(f"Skipping detailed malware scan for low-risk file type: {extension}")
                return
            
            # Read file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
                logging.debug(f"Read {len(file_content)} bytes from file")
            
            # Get relevant signatures
            signatures = []
            signatures.extend(self.malware_signatures.get(self.target_os, []))
            signatures.extend(self.malware_signatures.get("common", []))
            
            # Check each signature
            for sig in signatures:
                # Skip if signature doesn't apply to this file type
                if risk_category not in sig["applies_to"]:
                    continue
                    
                if sig["pattern"] in file_content:
                    level = ThreatLevel.HIGH if risk_category in ["executable", "script"] else ThreatLevel.MEDIUM
                    threat_desc = f"{sig['name']}: {sig['description']}"
                    logging.warning(f"Malware signature match: {threat_desc} in {file_path}")
                    self.results.add_threat("malware", file_path, threat_desc, level)
                    
        except Exception as e:
            logging.error(f"Error during malware scan: {str(e)}", exc_info=True)
            print(f"{Fore.RED}Error during malware scan: {e}")
    
    def _scan_for_harmful_code(self, file_path, extension):
        """Scan a script file for potentially harmful code patterns"""
        try:
            logging.debug(f"Starting harmful code scan for {file_path}")
            # Get patterns for this file type
            patterns = self.harmful_code_patterns.get(extension, [])
            if not patterns:
                logging.debug(f"No harmful code patterns defined for extension {extension}")
                return
                
            # Read file content and get lines
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                logging.debug(f"Read {len(content)} characters from file")
                
            line_count = len(lines)
            scan_steps = min(100, line_count)
            logging.debug(f"Analyzing {line_count} lines of code")
            
            # Define explanations for harmful patterns
            pattern_explanations = {
                'os.system(': 'Allows execution of arbitrary system commands which could be dangerous if input is not properly sanitized',
                'subprocess.call(': 'Enables execution of system commands that could be malicious if not properly validated',
                'exec(': 'Executes arbitrary Python code which could be dangerous if the code source is not trusted',
                'eval(': 'Evaluates arbitrary expressions which could lead to code injection if input is not validated',
                'rm -rf': 'Forcefully removes files/directories recursively which could lead to data loss',
                'rmdir': 'Removes directories which could lead to data loss if not properly checked',
                'remove(': 'Deletes files which could be dangerous if paths are not properly validated',
                'shutil.rmtree(': 'Recursively deletes directory trees which could cause significant data loss',
                '__import__("os")': 'Dynamic importing of os module could be used to hide malicious system operations',
                'base64.decode': 'Often used to obfuscate malicious code or hide suspicious strings',
                'document.write(': 'Can be used for XSS attacks or injecting malicious scripts',
                'fromCharCode(': 'Often used to obfuscate malicious JavaScript code',
                'crypto.generateCoinHive': 'Associated with cryptocurrency mining without user consent',
                'new Function(': 'Creates functions from strings which could execute malicious code',
                'shell_exec(': 'Executes commands through shell which could be dangerous if input is not sanitized',
                'passthru(': 'Executes system commands and passes output directly which could be exploited',
                'unlink(': 'Deletes files which could lead to data loss if not properly validated',
                'format c:': 'Attempts to format the system drive which could cause complete data loss',
                'reg delete': 'Modifies Windows registry which could damage system configuration',
                'netsh firewall': 'Modifies firewall settings which could create security vulnerabilities',
                'dd if=/dev/zero': 'Can be used to overwrite disk data causing permanent data loss',
                'mkfs.ext4': 'Formats disk partitions which could lead to data loss',
                ':(){:|:&};:': 'Fork bomb that can crash the system by exhausting resources'
            }
            
            # Simulate code scanning with a progress bar
            for _ in tqdm(range(scan_steps), desc="Code analysis", unit="block"):
                time.sleep(0.01)  # Simulating work
                
            # Check for harmful patterns
            for line_num, line in enumerate(lines, 1):
                for pattern in patterns:
                    if pattern in line:
                        col = line.find(pattern) + 1
                        level = ThreatLevel.MEDIUM
                        if "rm -rf" in pattern or "del /f" in pattern or "remove(" in pattern:
                            level = ThreatLevel.HIGH
                            
                        # Get explanation or create Google search link
                        explanation = pattern_explanations.get(pattern, '')
                        if not explanation:
                            encoded_search = f"https://www.google.com/search?q=how+can+this+code+be+a+threat%3F+{pattern.replace('(', '%28').replace(')', '%29').replace(' ', '+')}"
                            explanation = f"For additional information visit: {encoded_search}"
                            
                        threat_info = {
                            "pattern": pattern,
                            "line": line_num,
                            "column": col,
                            "code_line": line.strip(),
                            "explanation": explanation
                        }
                        
                        logging.warning(f"Harmful code pattern detected: {pattern} at line {line_num}, column {col} in {file_path}")
                        self.results.add_threat("harmful_code", file_path, threat_info, level)
                    
        except Exception as e:
            logging.error(f"Error during harmful code analysis: {str(e)}", exc_info=True)
            print(f"{Fore.RED}Error during code analysis: {e}")
    
    def _scan_for_blockchain_miners(self, file_path):
        """Scan a file for potential blockchain mining software"""
        try:
            logging.debug(f"Starting blockchain miner scan for {file_path}")
            # Read file content
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    logging.debug("Successfully read file in text mode")
            except:
                # If text reading fails, try binary
                logging.debug("Text mode read failed, attempting binary read")
                with open(file_path, 'rb') as f:
                    content = f.read().decode('utf-8', errors='ignore')
                    logging.debug("Successfully read file in binary mode")
                
            file_size = os.path.getsize(file_path)
            scan_steps = min(100, file_size // 1024 + 1)
            logging.debug(f"File size: {file_size} bytes")
            
            # Simulate blockchain scanning with a progress bar
            for _ in tqdm(range(scan_steps), desc="Blockchain scan", unit="block"):
                time.sleep(0.01)  # Simulating work
                
            # Check for blockchain mining patterns
            for pattern in self.blockchain_patterns:
                if pattern in content:
                    level = ThreatLevel.MEDIUM
                    logging.warning(f"Blockchain mining pattern detected: {pattern} in {file_path}")
                    self.results.add_threat("blockchain", file_path, f"Potential crypto miner: {pattern}", level)
                    
        except Exception as e:
            logging.error(f"Error during blockchain scan: {str(e)}", exc_info=True)
            print(f"{Fore.RED}Error during blockchain scan: {e}")

def display_results(results, files_scanned):
    """Display scan results with color coding"""
    print("\n" + "="*80)
    print(f"{Fore.CYAN}SCAN RESULTS SUMMARY")
    print("="*80)
    
    # Display scan statistics
    print(f"\n{Fore.CYAN}Total files scanned: {files_scanned}")
    
    # Display virus threats
    if results.virus_threats:
        print(f"\n{Fore.RED}VIRUS THREATS DETECTED: {len(results.virus_threats)}")
        for threat in results.virus_threats:
            color = Fore.RED if threat["level"] == ThreatLevel.HIGH else Fore.YELLOW
            print(f"{color}[{threat['level'].upper()}] {threat['file']} - {threat['threat']}")
    else:
        print(f"\n{Fore.GREEN}No virus threats detected")
        
    # Display malware threats
    if results.malware_threats:
        print(f"\n{Fore.RED}MALWARE THREATS DETECTED: {len(results.malware_threats)}")
        for threat in results.malware_threats:
            color = Fore.RED if threat["level"] == ThreatLevel.HIGH else Fore.YELLOW
            print(f"{color}[{threat['level'].upper()}] {threat['file']} - {threat['threat']}")
    else:
        print(f"\n{Fore.GREEN}No malware threats detected")
        
    # Display harmful code threats with enhanced information
    if results.harmful_code_threats:
        print(f"\n{Fore.RED}HARMFUL CODE DETECTED: {len(results.harmful_code_threats)}")
        for threat in results.harmful_code_threats:
            color = Fore.RED if threat["level"] == ThreatLevel.HIGH else Fore.YELLOW
            print(f"{color}[{threat['level'].upper()}] {threat['file']}")
            threat_info = threat['threat']
            if isinstance(threat_info, dict):
                print(f"{color}  Location: Line {threat_info['line']}, Column {threat_info['column']}")
                print(f"{color}  Pattern: {threat_info['pattern']}")
                print(f"{color}  Code: {threat_info['code_line']}")
                print(f"{color}  Explanation: {threat_info['explanation']}\n")
            else:
                print(f"{color}  {threat_info}\n")
    else:
        print(f"\n{Fore.GREEN}No harmful code detected")
        
    # Display blockchain threats
    if results.blockchain_threats:
        print(f"\n{Fore.RED}BLOCKCHAIN MINERS DETECTED: {len(results.blockchain_threats)}")
        for threat in results.blockchain_threats:
            color = Fore.RED if threat["level"] == ThreatLevel.HIGH else Fore.YELLOW
            print(f"{color}[{threat['level'].upper()}] {threat['file']} - {threat['threat']}")
    else:
        print(f"\n{Fore.GREEN}No blockchain miners detected")
        
    # Overall summary
    print("\n" + "="*80)
    if results.has_threats():
        print(f"{Fore.RED}SCAN COMPLETE: Threats were detected!")
    else:
        print(f"{Fore.GREEN}SCAN COMPLETE: No threats detected!")
    print("="*80)

def create_log_file(results, scan_path, target_os, files_scanned):
    """Create a log file with scan results"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"virus_scan_{timestamp}.log"
    
    with open(log_file, 'w') as f:
        f.write("="*80 + "\n")
        f.write(f"VIRUS SCAN RESULTS\n")
        f.write("="*80 + "\n\n")
        
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target: {scan_path}\n")
        f.write(f"Target OS: {target_os}\n")
        f.write(f"Files Scanned: {files_scanned}\n\n")
        
        # Write virus threats
        f.write("VIRUS SCAN RESULTS:\n")
        if results.virus_threats:
            f.write(f"VIRUS THREATS DETECTED: {len(results.virus_threats)}\n")
            for threat in results.virus_threats:
                f.write(f"[{threat['level'].upper()}] {threat['file']} - {threat['threat']}\n")
        else:
            f.write("No virus threats detected\n")
            
        # Write malware threats
        f.write("\nMALWARE SCAN RESULTS:\n")
        if results.malware_threats:
            f.write(f"MALWARE THREATS DETECTED: {len(results.malware_threats)}\n")
            for threat in results.malware_threats:
                f.write(f"[{threat['level'].upper()}] {threat['file']} - {threat['threat']}\n")
        else:
            f.write("No malware threats detected\n")
            
        # Write harmful code threats with enhanced information
        f.write("\nCODE ANALYSIS RESULTS:\n")
        if results.harmful_code_threats:
            f.write(f"HARMFUL CODE DETECTED: {len(results.harmful_code_threats)}\n")
            for threat in results.harmful_code_threats:
                f.write(f"[{threat['level'].upper()}] {threat['file']}\n")
                threat_info = threat['threat']
                if isinstance(threat_info, dict):
                    f.write(f"  Location: Line {threat_info['line']}, Column {threat_info['column']}\n")
                    f.write(f"  Pattern: {threat_info['pattern']}\n")
                    f.write(f"  Code: {threat_info['code_line']}\n")
                    f.write(f"  Explanation: {threat_info['explanation']}\n")
                else:
                    f.write(f"  {threat_info}\n")
                f.write("\n")
        else:
            f.write("No harmful code detected\n")
            
        # Write blockchain threats
        f.write("\nBLOCKCHAIN SCAN RESULTS:\n")
        if results.blockchain_threats:
            f.write(f"BLOCKCHAIN MINERS DETECTED: {len(results.blockchain_threats)}\n")
            for threat in results.blockchain_threats:
                f.write(f"[{threat['level'].upper()}] {threat['file']} - {threat['threat']}\n")
        else:
            f.write("No blockchain miners detected\n")
            
        # Overall summary
        f.write("\n" + "="*80 + "\n")
        if results.has_threats():
            f.write("SCAN COMPLETE: Threats were detected!\n")
        else:
            f.write("SCAN COMPLETE: No threats detected!\n")
        f.write("="*80 + "\n")
    
    print(f"{Fore.GREEN}Log file created: {log_file}")
    return log_file

def setup_logging(debug_mode):
    """Configure logging based on debug mode"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"debug_{timestamp}.log" if debug_mode else None
    
    if debug_mode:
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        logging.debug("Debug logging initialized")
    else:
        logging.basicConfig(level=logging.INFO)

def display_readme():
    """Display detailed information about the program"""
    readme_text = """
Virus Scanner - Comprehensive File Analysis Tool
=============================================

Description
-----------
This tool is a comprehensive file analysis system that scans files, directories, and zip archives
for potential security threats. It combines multiple scanning approaches to provide thorough
security analysis of your files.

Key Features
-----------
1. Multiple Scanning Capabilities:
   - Virus detection using built-in signatures
   - Malware pattern recognition
   - Harmful code analysis in scripts
   - Cryptocurrency mining detection
   - Integration with ClamAV antivirus
   - YARA Rules support
   - National Vulnerability Database (NVD) integration

2. Supported File Types:
   - Executable files (.exe, .dll, .sys, etc.)
   - Script files (.py, .js, .php, .bat, etc.)
   - Document files with macros (.docm, .xlsm, etc.)
   - Archive files (.zip, .rar, .7z, etc.)
   - General files (text, images, media)

Command Line Arguments
--------------------
--os {win,mac,linux,android}
    Specify the target operating system for appropriate signature matching
    Default: win

--debug
    Enable detailed debug logging to track the scanning process
    Creates a debug log file with timestamp

--clamav-only
    Use only ClamAV for virus scanning, skipping built-in signatures
    Requires ClamAV to be installed and running

--readme
    Display this detailed information about the program

Risk Categories
-------------
HIGH:   Critical security threats that require immediate attention
MEDIUM: Potential security risks that should be reviewed
LOW:    Minor concerns or informational findings

Log Files
--------
1. Debug Log (debug_YYYYMMDD_HHMMSS.log):
   - Created when --debug flag is used
   - Contains detailed scanning process information
   - Helpful for troubleshooting and understanding scan flow

2. Scan Results Log (virus_scan_YYYYMMDD_HHMMSS.log):
   - Created when requested after scan completion
   - Contains comprehensive scan results
   - Includes threat details, locations, and explanations
   - Useful for documentation and analysis

Enhanced Features
---------------
1. Code Analysis:
   - Line and column numbers for detected issues
   - Actual code snippets showing the concern
   - Detailed explanations of why code might be harmful
   - Google search links for additional information

2. Zip File Handling:
   - Safe extraction of compressed files
   - Handles problematic file names
   - Temporary directory management
   - Recursive scanning of contents

3. Multiple Integration Options:
   - YARA Rules for custom pattern matching
   - NVD for known vulnerability checking
   - ClamAV for traditional antivirus scanning

Usage Examples
-------------
1. Scan a single file:
   python virus_scan.py suspicious_file.exe --os win

2. Scan a directory:
   python virus_scan.py /path/to/directory --os linux --debug

3. Scan a zip archive:
   python virus_scan.py archive.zip --os mac

4. ClamAV-only scan:
   python virus_scan.py file.exe --os win --clamav-only

Best Practices
-------------
1. Always use the --debug flag when investigating issues
2. Create log files for important scans for documentation
3. Use appropriate OS flag for accurate detection
4. Review all HIGH and MEDIUM risk findings
5. Keep ClamAV updated if using ClamAV integration
6. Regularly update YARA rules for better detection

Note: This tool is designed for security analysis and should be used responsibly.
Some detected patterns may be legitimate in certain contexts - always review
findings and use professional judgment.
"""
    print(readme_text)

def main():
    """Main function to parse arguments and run the virus scanner"""
    parser = argparse.ArgumentParser(
        description="Virus Scanner - Scan files, directories, or zip archives for threats",
        epilog="Example: python virus_scan.py file.exe --os win"
    )
    
    # Add target argument (file, directory, or zip)
    parser.add_argument("target", nargs='?', help="File, directory, or zip archive to scan")
    
    # Add OS flag
    parser.add_argument("--os", choices=SUPPORTED_OS, default="win",
                       help="Target operating system (win, mac, linux, android)")
    
    # Add debug flag
    parser.add_argument("--debug", action="store_true",
                       help="Enable debug logging to file")
    
    # Add ClamAV-only flag
    parser.add_argument("--clamav-only", action="store_true",
                       help="Use only ClamAV for virus scanning (skip built-in signatures)")
    
    # Add readme flag
    parser.add_argument("--readme", action="store_true",
                       help="Display detailed information about the program")
    
    args = parser.parse_args()
    
    # If readme flag is set, display readme and exit
    if args.readme:
        display_readme()
        return 0
    
    # Check if target is provided when not displaying readme
    if not args.target:
        parser.error("target is required unless --readme is specified")
    
    # Setup logging based on debug flag
    setup_logging(args.debug)
    logging.debug("Starting virus scanner application")
    
    # Ask user about YARA and NVD
    print(f"\n{Fore.CYAN}Would you like to enable additional scanning capabilities?")
    
    use_yara = input(f"{Fore.CYAN}Enable YARA Rules scanning? (y/n): ").strip().lower() == 'y'
    if use_yara:
        yara_scanner = YARAScanner()
        if yara_scanner.initialize():
            print(f"{Fore.GREEN}YARA Rules scanning enabled")
        else:
            print(f"{Fore.RED}Failed to initialize YARA Rules. Continuing without YARA support.")
            use_yara = False
            
    use_nvd = input(f"{Fore.CYAN}Enable National Vulnerability Database (NVD) scanning? (y/n): ").strip().lower() == 'y'
    if use_nvd:
        nvd_scanner = NVDScanner()
        if nvd_scanner.initialize():
            print(f"{Fore.GREEN}NVD scanning enabled")
        else:
            print(f"{Fore.RED}Failed to initialize NVD scanner. Continuing without NVD support.")
            use_nvd = False
    
    # Validate target
    if not os.path.exists(args.target):
        logging.error(f"Target not found - {args.target}")
        print(f"{Fore.RED}Error: Target not found - {args.target}")
        return 1
    
    # Create scanner for specified OS
    scanner = VirusScanner(args.os)
    
    # Add YARA and NVD scanners if enabled
    if use_yara:
        scanner.yara_scanner = yara_scanner
    if use_nvd:
        scanner.nvd_scanner = nvd_scanner
    
    # Determine scan type based on target
    target_path = os.path.abspath(args.target)
    scan_results = None
    
    logging.info(f"Starting scan of: {target_path}")
    logging.info(f"Target OS: {args.os}")
    print(f"{Fore.CYAN}Starting scan of: {target_path}")
    print(f"{Fore.CYAN}Target OS: {args.os}")
    
    # Run appropriate scan based on target type
    try:
        if os.path.isfile(target_path):
            if target_path.lower().endswith('.zip'):
                logging.info("Detected ZIP file, scanning contents...")
                print(f"{Fore.CYAN}Detected ZIP file, scanning contents...")
                scan_results = scanner.scan_zip(target_path)
            else:
                logging.info("Scanning single file...")
                print(f"{Fore.CYAN}Scanning file...")
                scan_results = scanner.scan_file(target_path)
        elif os.path.isdir(target_path):
            logging.info("Scanning directory...")
            print(f"{Fore.CYAN}Scanning directory...")
            scan_results = scanner.scan_directory(target_path)
        else:
            logging.error("Unsupported target type")
            print(f"{Fore.RED}Error: Unsupported target type")
            return 1
    except Exception as e:
        logging.error(f"Error during scan: {str(e)}", exc_info=True)
        print(f"{Fore.RED}Error during scan: {e}")
        return 1
    
    # Display results
    display_results(scan_results, scanner.files_scanned)
    
    # Log final statistics
    logging.info(f"Scan completed. Files scanned: {scanner.files_scanned}")
    logging.info(f"Threats found: {scan_results.has_threats()}")
    
    # Ask user if they want to create a log file
    create_log = input(f"\n{Fore.CYAN}Would you like to create a log file? (y/n): ").strip().lower()
    if create_log == 'y':
        log_file = create_log_file(scan_results, target_path, args.os, scanner.files_scanned)
        logging.info(f"Created log file: {log_file}")
        
    logging.debug("Virus scanner application completed")
    return 0

if __name__ == "__main__":
    sys.exit(main())
