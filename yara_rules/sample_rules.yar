/*
    Sample YARA rules for virus scanner
    These rules demonstrate common malware detection patterns
*/

rule SuspiciousStrings {
    meta:
        description = "Detects suspicious command strings"
        author = "Virus Scanner Project"
        date = "2024-01"
        severity = "medium"
    
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
    meta:
        description = "Detects potential malware indicators"
        author = "Virus Scanner Project"
        date = "2024-01"
        severity = "high"
    
    strings:
        $mal1 = "CreateRemoteThread"
        $mal2 = "VirtualAlloc"
        $mal3 = "WriteProcessMemory"
        $enc1 = "base64" nocase
        $enc2 = "encrypt" nocase
        
    condition:
        2 of them
}

rule CryptoMiner {
    meta:
        description = "Detects cryptocurrency mining indicators"
        author = "Virus Scanner Project"
        date = "2024-01"
        severity = "high"
    
    strings:
        $miner1 = "stratum+tcp://" nocase
        $miner2 = "xmrig" nocase
        $miner3 = "cryptonight" nocase
        $miner4 = "minexmr.com" nocase
        $miner5 = "coinhive" nocase
        
    condition:
        any of them
}

rule SuspiciousScriptContent {
    meta:
        description = "Detects suspicious content in scripts"
        author = "Virus Scanner Project"
        date = "2024-01"
        severity = "medium"
    
    strings:
        $script1 = "eval(" nocase
        $script2 = "exec(" nocase
        $script3 = "system(" nocase
        $script4 = "shell_exec(" nocase
        $script5 = "WScript.Shell" nocase
        
    condition:
        any of them
}

rule FileModification {
    meta:
        description = "Detects suspicious file operations"
        author = "Virus Scanner Project"
        date = "2024-01"
        severity = "medium"
    
    strings:
        $file1 = "DeleteFile" nocase
        $file2 = "RemoveDirectory" nocase
        $file3 = "format c:" nocase
        $file4 = "rm -rf" nocase
        $file5 = "unlink(" nocase
        
    condition:
        any of them
}
