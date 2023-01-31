#show extensions
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Value 0
Get-Process explorer | Stop-Process
Start-Process explorer

# Add user in domain
Import-Module ActiveDirectory

$username = "ansible"
$password = ConvertTo-SecureString "ansible" -AsPlainText -Force
$ou = "OU=00-Administration,OU=01-Employees,OU=00-Factory,DC=factory,DC=local"

try {
  New-ADUser -Name $username -AccountPassword $password -Enabled $true -Path $ou
  Add-ADPrincipalGroupMembership -Identity $username -MemberOf "Administrators"
  Write-Host "User $username created and added to the Administrators group successfully."
} catch {
  Write-Host "An error occurred while creating the user or adding the user to the Administrators group: $_"
}


#Add User for ansible and place it in administrators group
$username = "ansible"
$password = ConvertTo-SecureString "ansible" -AsPlainText -Force
$user = New-LocalUser -Name $username -Password $password
Add-LocalGroupMember -Group "Administrators" -Member $user

net users
net localgroup administrators
# ---------------------------------------------

#Add user ansible with password ansible in domain "factory.local"

# Import the Server Manager module
Import-Module ServerManager

# Add the Active Directory Domain Services role
Add-WindowsFeature -Name AD-Domain-Services

# Add the Remote Server Administration Tools feature
Add-WindowsFeature -Name RSAT-AD-Tools

# Restart the machine to complete the installation
Restart-Computer

$username = "ansible"
$password = ConvertTo-SecureString "ansible" -AsPlainText -Force
$domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain

New-ADUser -Name $username -AccountPassword $password -Enabled $true -Path "DC=$domain"
Add-ADPrincipalGroupMembership -Identity $username -MemberOf "Administrators"




#=================================================================================================================
#=================================================================================================================

#------------------ WINRM for HTTPS SSL traffic.
#Add firewall rule for winrm HTTPS traffic on port 5986
#New-NetFirewallRule -DisplayName "Allow WinRM HTTP Port 5986" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow

# Create a self-signed certificate
#$cert = New-SelfSignedCertificate -Subject "CN=$env:HOSTNAME, O=MyOrganization, L=MyCity" -CertStoreLocation "Cert:\LocalMachine\My" -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"

# Get the thumbprint of the certificate
#$thumbprint = $cert.Thumbprint

# Create a WinRM listener on HTTPS
#winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname="$env:HOSTNAME";CertificateThumbprint="$thumbprint"}

# Restart the WinRM service
#Restart-Service WinRM

#------------------ Verion With no certs using HTTP
#Add firewall rule for winrm HTTP traffic on port 5985
New-NetFirewallRule -DisplayName "Allow WinRM HTTP Port 5985" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow

# Disable the WinRM HTTPS listener by running the following command in PowerShell as administrator
Set-Item WSMan:\localhost\Service\Auth\Certificate -Value $false

#Before start HTTP listener network config must be changed to private!
#Change the network profile to "Private" if it is "Public" or "unidentified"

$networkProfile = (Get-NetConnectionProfile).Name
if ($networkProfile -eq "Public" -or $networkProfile -eq "Unidentified network") {
  Set-NetConnectionProfile -NetworkCategory Private
  Write-Host "The network profile was successfully changed to 'Private'"
} else {
  Write-Host "The network profile is already 'Private'"
}
Write-Output "The current network profile is: $networkProfile"

#Start the WinRM HTTP listener

Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value True

# Restart the WinRM service
Restart-Service WinRM

Write-Host "Check winrm listener ............ :"
winrm enumerate winrm/config/Listener

#=================================================================================================================
#=================================================================================================================
#Add Path for pyton and pip before instalation, because later in instalation python and pip wont know their location, win powershell rr is needed then.

# PATH 
[Environment]::SetEnvironmentVariable("Path", "$env:Path;C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python311\Scripts\;C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python311\", "User")

# PYTHONPATH list of directories that Python looks in for modules and packages
[Environment]::SetEnvironmentVariable("PYTHONPATH", "C:\Users\$env:USERNAME\Lib;C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python311\Lib", "User")

# PYTHONHOME location of the Python installation on your system
[Environment]::SetEnvironmentVariable("PYTHONHOME", "C:\Users\$env:USERNAME\Lib;C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python311", "User")

#Add pip to path
[Environment]::SetEnvironmentVariable("Path", "$env:Path;C:\Users\$env:USERNAME\AppData\Roaming\Python\Python311\Scripts", "User")

#=================================================================================================================
#=================================================================================================================
#Python instalation, pip3 instalation, and Ansible instalation

# Download Python installer adjust link and filename to latest version!
$url = "https://www.python.org/ftp/python/3.11.1/python-3.11.1-amd64.exe"
$output = "C:\python-3.11.1-amd64.exe"
Invoke-WebRequest -Uri $url -OutFile $output

# Install pip
Invoke-WebRequest https://bootstrap.pypa.io/get-pip.py -OutFile get-pip.py
python get-pip.py --user

#Install ansible
python -m pip install --user ansible










