import unittest
import os
import tempfile
import sys
from pathlib import Path

# Add parent directory to path so we can import virus_scan
sys.path.insert(0, str(Path(__file__).parent.parent))

from virus_scan import ThreatLevel, ScanResult, VirusScanner

class TestScanResult(unittest.TestCase):
    """Test cases for ScanResult class"""
    
    def test_init(self):
        """Test initialization of ScanResult"""
        result = ScanResult()
        self.assertEqual(len(result.virus_threats), 0)
        self.assertEqual(len(result.malware_threats), 0)
        self.assertEqual(len(result.harmful_code_threats), 0)
        self.assertEqual(len(result.blockchain_threats), 0)
        
    def test_has_threats(self):
        """Test has_threats method"""
        result = ScanResult()
        self.assertFalse(result.has_threats())
        
        # Add a virus threat
        result.add_threat("virus", "test.exe", "test_virus", ThreatLevel.HIGH)
        self.assertTrue(result.has_threats())
        
    def test_add_threat(self):
        """Test add_threat method"""
        result = ScanResult()
        
        # Add a virus threat
        result.add_threat("virus", "test.exe", "test_virus", ThreatLevel.HIGH)
        self.assertEqual(len(result.virus_threats), 1)
        self.assertEqual(result.virus_threats[0]["file"], "test.exe")
        self.assertEqual(result.virus_threats[0]["threat"], "test_virus")
        self.assertEqual(result.virus_threats[0]["level"], ThreatLevel.HIGH)
        
        # Add a malware threat
        result.add_threat("malware", "test.dll", "test_malware", ThreatLevel.MEDIUM)
        self.assertEqual(len(result.malware_threats), 1)
        self.assertEqual(result.malware_threats[0]["file"], "test.dll")
        
        # Add a harmful code threat
        result.add_threat("harmful_code", "test.py", "test_code", ThreatLevel.LOW)
        self.assertEqual(len(result.harmful_code_threats), 1)
        
        # Add a blockchain threat
        result.add_threat("blockchain", "test.bin", "test_miner", ThreatLevel.MEDIUM)
        self.assertEqual(len(result.blockchain_threats), 1)
        
class TestVirusScanner(unittest.TestCase):
    """Test cases for VirusScanner class"""
    
    def setUp(self):
        """Set up test environment"""
        self.scanner = VirusScanner("win")
        
        # Create a temporary directory
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a test file
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "w") as f:
            f.write("This is a test file.")
            
        # Create a test script
        self.test_script = os.path.join(self.temp_dir, "test.py")
        with open(self.test_script, "w") as f:
            f.write("print('Hello, world!')")
            
    def tearDown(self):
        """Clean up after tests"""
        # Remove test files
        os.remove(self.test_file)
        os.remove(self.test_script)
        
        # Remove test directory
        os.rmdir(self.temp_dir)
        
    def test_scanner_init(self):
        """Test initialization of VirusScanner"""
        self.assertEqual(self.scanner.target_os, "win")
        self.assertIsInstance(self.scanner.results, ScanResult)
        
    def test_scan_file(self):
        """Test scan_file method"""
        # Since our scanner uses random detection for demo purposes,
        # we can't easily test the actual detection. We can verify it runs.
        results = self.scanner.scan_file(self.test_file)
        self.assertIsInstance(results, ScanResult)
        
if __name__ == "__main__":
    unittest.main() 