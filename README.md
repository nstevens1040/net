# Net
PowerShell script to gather information about your current local area network, your current subnet, assigned IP addresses, and available IP addresses.  
# Usage
```ps1
Set-ExecutionPolicy Bypass -Scope Process -Force;
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;
iex (irm https://net.nanick.org/subnetting.ps1)
```
