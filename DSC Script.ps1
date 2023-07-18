#########################################################
# Logging Config                                        #
#########################################################

$Logfiledebug = "c:\temp\builddebug.log"
$Logfileout = "c:\temp\buildoutput.log"

Function LogWrite
{
   Param ([string]$logstring)
   $logdate = $(Get-Date -Format u)
   $logentry = $logdate + " - " + $logstring
   Add-content $Logfiledebug -value $logentry
}


# Establish VPC from subnet 3rd octet (refer to AWS VPC subnets)
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
$instanceip = Invoke-RestMethod -uri http://169.254.169.254/latest/meta-data/local-ipv4
$instanceip = $instanceip.Split(".")
$octet = [int]$instanceip[2]


# Check prod
if ($octet -ge 32 -and $octet -le 62) {
    $instanceenv = "Prod"
}

# Check Nonprod
elseif ($octet -ge 96 -and $octet -le 120) {
    $instanceenv = "NonProd"
}

else {
    $instanceenv = "NonProd"
}
# Check DMZ - Future, needs Extranet function
#if ($octet -ge 128 -and $octet -le 156) {
#    $instanceenv = "DMZ"
#}

#########################################################
# Baseline Phase                                        #
#########################################################

#Create Baseline folders
$folderbatch = Test-Path c:\batch
$foldertemp = Test-Path c:\temp
$folderDSC = Test-Path c:\temp\DSC
if($foldertemp -eq $False){
    LogWrite "INFO : Creating Temp Folder"
    New-Item c:\temp -type directory
}
if($folderbatch -eq $False){
    LogWrite "INFO : Creating Batch Folder"
    New-Item c:\batch -type directory
}

if($folderDSC -eq $False){
    LogWrite "INFO : Creating DSC Folder"
    New-Item c:\temp\DSC -type directory
}

# Check if BuildComplete bit is sent
if (Get-ItemProperty -Path HKLM:Software\DSGBuild -Name BuildComplete -ErrorAction SilentlyContinue) {
    LogWrite "INFO : BuildComplete reg setting detected, exiting"
    exit
} 

# Set Regkeys
if (Test-Path HKLM:Software\DSGBuild) {
    LogWrite "INFO : HKLM:\Software\DSGBuild already exists"
}
else {
    New-Item -Path HKLM:Software -Name DSGBuild
    LogWrite "INFO : Creating HKLM:\Software\DSGBuild"
}
if (Get-ItemProperty -Path HKLM:Software\DSGBuild -Name Deploy -ErrorAction SilentlyContinue) {
    LogWrite "INFO : HKLM:\Software\DSGBuild\Deploy already exists"
} 
else {
    New-ItemProperty -Path HKLM:Software\DSGBuild -Name Deploy -PropertyType DWord -Value 1 -Force
    LogWrite "INFO : Creating HKLM:\Software\DSGBuild\Deploy"
}
if (Get-ItemProperty -Path HKLM:Software\DSGBuild -Name Bootloop -ErrorAction SilentlyContinue) {
    LogWrite "INFO : HKLM:\Software\DSGBuild\Bootloop already exists"
} 
else {
    New-ItemProperty -Path HKLM:Software\DSGBuild -Name Bootloop -PropertyType DWord -Value 0 -Force
    LogWrite "INFO : Creating HKLM:\Software\DSGBuild\Bootloop"
}

#Test network connectivity before proceeding
$defaultgw = Get-WmiObject -Class Win32_IP4RouteTable |
where { $_.destination -eq '0.0.0.0' -and $_.mask -eq '0.0.0.0'} |
Sort-Object metric1 | select nexthop
$defaultgw = $defaultgw.nexthop
$goodconn = Test-Connection $defaultgw -Count 1 -ErrorAction SilentlyContinue
if ($goodconn -eq $null){
    LogWrite "ERROR : Cannot connect to default gateway, reboot and try and again"
}

#Determine OS Version
$wmiOS = Get-WmiObject -Class Win32_OperatingSystem
$wmiOS = $wmiOS.version
$os = "2000"
if ($wmiOS.substring(0,3) -eq "6.3") {$os = "2012"}
if ($wmiOS.substring(0,4) -eq "10.0") {$os = "2016"}

#Drop PS Executation Policy
Set-ExecutionPolicy -executionpolicy Unrestricted -force
LogWrite "INFO : Setting Execution Policy to : Unrestricted"

#Determine PS Version
$psversioncheck = $PSVersionTable.PSVersion.Major
LogWrite "INFO : Detected Powershell version is $psversioncheck"

#Install Chocolatey
$chocoinstalled = Test-Path C:\ProgramData\chocolatey\bin\choco.exe
LogWrite "INFO : Choco install check is : $chocoinstalled"
if ($chocoinstalled -eq $False){
    LogWrite "INFO : Installing Choco"
    $chocoinstalllog = iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
    LogWrite "########"
    LogWrite "Choco Install Log"
    LogWrite $chocoinstalllog
    LogWrite "########"
    #Disable Choco Global Confirms
    choco feature enable -n=allowGlobalConfirmation
    LogWrite "INFO : Enable Choco Global confirm suppression"
}


#Install AWSCLI
$checkinstall = Test-Path 'C:\Program Files\Amazon\AWSCLI'
LogWrite "INFO : AWSCLI path check is : $checkinstall"
if ($checkinstall -ne $True){
    LogWrite "INFO : Installing AWSCLI"
    choco install awscli
    choco install AWSTools.Powershell
}


#Install Powershell 5 if 2012
if($os -eq "2012" -and $psversioncheck -lt 5) {
    LogWrite "INFO : Installing Powershell"
    choco install Powershell
    "INFO : Rebooting"
    Restart-Computer -Force
    exit
}

#Kill pointless Maps Broker service that crashes too much
if($os -eq "2016"){
    LogWrite "INFO : Killing Maps Broker Service"
    Get-Service -Name MapsBroker | Set-Service -StartupType Disabled -Confirm:$false
}

#Disable UAC
$UACStatus = Get-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -ErrorAction SilentlyContinue
$UACStatus = $UACStatus.EnableLUA
if ($UACStatus -eq 1) {
    LogWrite "INFO : Disabling UAC"
    New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
}
else {
    LogWrite "INFO : UAC already disabled"
}

#Set environment variables
LogWrite "INFO : Setting environment variables for TMP and TEMP"
$temp = [Environment]::GetEnvironmentVariable("TEMP")
$tmp = [Environment]::GetEnvironmentVariable("TMP")
$temp += ";C:\temp\"
$tmp += ";C:\temp\"
[Environment]::SetEnvironmentVariable("TEMP",$temp)
[Environment]::SetEnvironmentVariable("TMP",$tmp)

# Disable IPv6
LogWrite "INFO : Unbinding IPv6 from NICs"
$validadapters = Get-NetAdapterBinding | 
select InterfaceDescription, ComponentID, Enabled |
where {$_.Enabled -eq $True -and $_.ComponentID -eq "ms_tcpip6"}
foreach ($adapter in $validadapters){
    Disable-NetAdapterBinding -InterfaceDescription $adapter.InterfaceDescription -ComponentID ms_tcpip6
    write-host "INFO : Removing IPv6 from adapter : "$adapter.InterfaceDescription
}

# Disable SMBv1 (Very dangerous)	
LogWrite "INFO : Disabling SMBv1"
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Drops Windows Firewall
LogWrite "INFO : Disabling Firewall"
$DomainProfile = Get-NetFirewallProfile -Profile Domain
$PublicProfile = Get-NetFirewallProfile -Profile Public
$PrivateProfile = Get-NetFirewallProfile -Profile Private
$DomainProfile = $DomainProfile.Enabled
LogWrite "INFO : Firewall : Domain profile enabled is $DomainProfile"
$PublicProfile = $PublicProfile.Enabled
LogWrite "INFO : Firewall : Public profile enabled is $PublicProfile"
$PrivateProfile = $PrivateProfile.Enabled
LogWrite "INFO : Firewall : Private profile enabled is $PrivateProfile"

if ($DomainProfile -eq "True" -or $PublicProfile -eq "True" -or $PrivateProfile -eq "True"){
    LogWrite "INFO : Firewall : Disabling firewall profiles"
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
}

# Add LS-SVR-Windows-LocalAdmins to local Administrators group on server
Add-LocalGroupMember -Group "Administrators" -Member "S-1-5-21-1220945662-746137067-682003330-107938" -ErrorAction SilentlyContinue
LogWrite "INFO : Adding LS-SVR-Windows-LocalAdmins to local admins"

#Adds VOLSUP User account to local admin
$checkvolsup = get-localuser | where {$_.Name -eq "vOLSUP"}
if ($checkvolsup -eq $null){
    LogWrite "INFO : Setting volsup"
    $ReadParamStore = Get-SSMParameterValue -Name "/prod/volsup" -WithDecryption $True
    $Password = $ReadParamStore.Parameters[0].Value
    $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
    New-LocalUser -Name "vOLSUP" -Description "volsup" -Password $SecurePassword
    Add-LocalGroupMember -Group "Administrators" -Member "vOLSUP"
}

#########################################################
# International section needs work with reg keys        #
#########################################################

# Import 'International' module to Powershell session
#write-host "INFO : Setting International Settings"
#Import-Module International

# Set regional format (date/time etc.) to English (Australia) - this applies to all users
#Set-Culture en-AU
#Set-WinUserLanguageList en-AU -Force
#Set-WinHomeLocation -GeoId 0xC
LogWrite "INFO : Setting timezone to Adelaide"
Set-TimeZone -Name "Cen. Australia Standard Time"

# Check language list for non-US input languages, exit if found
#$currentlist = Get-WinUserLanguageList
#$currentlist | ForEach-Object {if(($_.LanguageTag -ne "en-AU") -and ($_.LanguageTag -ne "en-US")){exit}}

# Install Windows Backup
LogWrite "INFO : Installing Windows Server Backup"
Install-WindowsFeature -Name Windows-Server-Backup

# Install Active Directory Powershell Modules
LogWrite "INFO : Installing Active Directory PowerShell modules"
Add-WindowsFeature RSAT-AD-PowerShell

# Disable IE ESC
#$AdminKey = “HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}”
#$UserKey = “HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}”
#Set-ItemProperty -Path $AdminKey -Name “IsInstalled” -Value 0
#Set-ItemProperty -Path $UserKey -Name “IsInstalled” -Value 0
#LogWrite "INFO : Disabling IE ESC"

#Return Execution Policy
Set-ExecutionPolicy -executionpolicy RemoteSigned -force
LogWrite "INFO : Restoring Execution Policy to Remotesigned"

#Rename Computer to incoming name
if ($hostname -eq $null){
    LogWrite "ERROR : No hostname found"
    exit
}
else {
    Rename-Computer -NewName $hostname
    LogWrite "INFO : Renaming computer to $hostname"
}

#Reboot 1 before Domain Join Phase
$bootloopcount  = Get-ItemProperty -Path HKLM:Software\DSGBuild -Name Bootloop
$bootloopcount = $bootloopcount.Bootloop + 1
if ($bootloopcount -le 1) {
    New-ItemProperty -Path HKLM:Software\DSGBuild -Name Bootloop -PropertyType DWord -Value $bootloopcount -Force
    LogWrite "INFO : Rebooting (1)"
    Restart-Computer -Force
    exit
}

#########################################################
# Domain Join Phase                                     #
#########################################################

#Check if domain joined already
$domainjoincheck = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
LogWrite "INFO : Domain joined check is $domainjoincheck"
if($domainjoincheck -ne $True) {
    # Get proposed computer name
    if ($hostname -eq $null){
        LogWrite "ERROR : No hostname found, fix up the User Data input"
        exit
    }

    # Check length doesnt exceed 15 chars
    if ($hostname.Length -gt 15) {
        LogWrite "ERROR : Please use a hostname of 15 characters or less and try again, stopping"
        exit
    }

    # Establish desired domain controller, specific the AD site name to discover DCs
    $sitename = "AWS"
    $domainname = "mydomain.com"
    $validDC = resolve-dnsname -name "_ldap._tcp.$sitename._sites.dc._msdcs.$domainname" -type srv | select NameTarget
    if ($validDC -eq $null) {
        LogWrite "ERROR : Cant find a valid DC, quitting"
        exit
    }
    else {
        $logDC = $validDC[0].NameTarget
        LogWrite "INFO : Selected DC is "$logDC
    }

    # Domain Join Creds
    $ReadParamStore = Get-SSMParameterValue -Name "/prod/svs_domain_join" -WithDecryption $True
    $Password = $ReadParamStore.Parameters[0].Value
    $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
    $DomJoinCreds = New-Object System.Management.Automation.PSCredential ("mydomain\SVS_DOMAIN_JOIN", $SecurePassword )
    LogWrite "INFO : Obtaining domain join credentials"

    #Join Domain
    if($instanceenv -eq "Prod"){
        $OUPath = "OU=Application Servers,OU=Member Servers Admin,DC=mydomain,DC=com"
    }
    elseif ($instanceenv -eq "NonProd"){
        $OUPath = "OU=Development & Test,OU=Member Servers Admin,DC=mydomain,DC=com"
    }
    else {
        $OUPath = "OU=Development & Test,OU=Member Servers Admin,DC=mydomain,DC=com"
    }
    Add-Computer -DomainName $domainname -server $validDC[0].NameTarget -OUPath $OUPath -Credential $DomJoinCreds
    LogWrite "INFO : Joining Domain"
    New-ItemProperty -Path HKLM:Software\DSGBuild -Name DCUsed -Value $validDC[0].NameTarget -Force
}

# Reboot 2 before tidy up
$bootloopcount  = Get-ItemProperty -Path HKLM:Software\DSGBuild -Name Bootloop
$bootloopcount = $bootloopcount.Bootloop + 1
if ($bootloopcount -le 2) {
    New-ItemProperty -Path HKLM:Software\DSGBuild -Name Bootloop -PropertyType DWord -Value $bootloopcount -Force
    LogWrite "INFO : Rebooting (2)"
    Restart-Computer -Force
    exit
}

#########################################################
# Post Domain Join Phase                                #
#########################################################

#Add to WSUS Group (NEED PERMISSIONS)
#if($production = $True){
#    $patchgroup = "LS-WSUS-WeeklySun-GP"
#}
#else{    $patchgroup = "LS-WSUS-WeeklySat-GP"
#}
#$usedDC = Get-ItemProperty -Path HKLM:Software\DSGBuild -Name DCUsed -ErrorAction SilentlyContinue
#$usedDC = $usedDC.DCUsed
#$ADcomputeraccount = Get-ADComputer -server $usedDC -Filter {Name -eq $hostname}
#if ((Get-ADComputer $hostname -Properties MemberOf -server $usedDC | select -ExpandProperty MemberOf) -notcontains $patchgroup) {
#    $ReadParamStore = Get-SSMParameterValue -Name "/prod/svs_groupmembership" -WithDecryption $True
#    $Password = $ReadParamStore.Parameters[0].Value
#    $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
#    $DomJoinCreds = New-Object System.Management.Automation.PSCredential ("MYDOMAIN\svs_groupmembership", $SecurePassword )
#    Add-ADGroupMember -Identity $patchgroup -Members $ADcomputeraccount -Credential $DomJoinCreds
#}

# Wait for machine to be ready
Start-Sleep -Seconds 90

# Configure LCM for DSC pull server
(new-object net.webclient).DownloadFile('https://s3-ap-southeast-2.amazonaws.com/ict-prod-winlaunch-syd/LAPS.x64.msi','c:\temp\LAPS.x64.msi')

if($instanceenv -eq "Prod" -Or $instanceenv -eq "DMZ"){
    (new-object net.webclient).DownloadFile('https://s3-ap-southeast-2.amazonaws.com/ict-prod-winlaunch-syd/agent_cloud_x64_prod.msi','c:\temp\DSC\agent_cloud_x64_prod.msi')
    (new-object net.webclient).DownloadFile('https://s3-ap-southeast-2.amazonaws.com/ict-prod-winlaunch-syd/localhost_mof/prod/localhost.meta.mof','C:\Temp\DSC\localhost.meta.mof')
    Set-DscLocalConfigurationManager -Path C:\Temp\DSC
    LogWrite "OUTPUT : DSC configuration completed for Production server"
}
else {
    (new-object net.webclient).DownloadFile('https://s3-ap-southeast-2.amazonaws.com/ict-prod-winlaunch-syd/agent_cloud_x64_nonprod.msi','c:\temp\DSC\agent_cloud_x64_nonprod.msi')
    (new-object net.webclient).DownloadFile('https://s3-ap-southeast-2.amazonaws.com/ict-prod-winlaunch-syd/localhost_mof/nonprod/localhost.meta.mof','C:\Temp\DSC\localhost.meta.mof')
    Set-DscLocalConfigurationManager -Path C:\Temp\DSC
    LogWrite "OUTPUT : DSC configuration completed for Non-production server"
}


# Reboot 3 before tidy up
$bootloopcount  = Get-ItemProperty -Path HKLM:Software\DSGBuild -Name Bootloop
$bootloopcount = $bootloopcount.Bootloop + 1
if ($bootloopcount -le 3) {
    New-ItemProperty -Path HKLM:Software\DSGBuild -Name Bootloop -PropertyType DWord -Value $bootloopcount -Force
    LogWrite "INFO : Rebooting (3)"
    Restart-Computer -Force
    exit
}


LogWrite "INFO : Starting Test phase"
#########################################################
# Post Build Checks NB: Most of these tests should be 
# converted to functions                                 
#########################################################

Logwrite "############"
# Test hostname
$hostname = hostname
Logwrite "OUTPUT : Hostname is : $hostname"

# Test Production state
$hostname = hostname
Logwrite "OUTPUT : Instanceenv flag is : $instanceenv"

# Test domain join
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
Logwrite "OUTPUT : $hostname is joined to : $domain"

# Test Used DC
$usedDC = Get-ItemProperty -Path HKLM:Software\DSGBuild -Name DCUsed -ErrorAction SilentlyContinue
$usedDC = $usedDC.DCUsed
Logwrite "OUTPUT : Domain Controller used was $usedDC"

# Test OS version
Logwrite "OUTPUT : Server is running Windows Server $os family"

# Test Powenshell 
$psversioncheck = $PSVersionTable.PSVersion.Major
Logwrite "OUTPUT : Server is running Powershell version $psversioncheck"

# Test Exec Policy
$execpolicy = Get-ExecutionPolicy -Scope LocalMachine
Logwrite "OUTPUT : Execution Policy is $execpolicy"

# Test Choco
$chocoinstalled = Test-Path C:\ProgramData\chocolatey\bin\choco.exe
Logwrite "OUTPUT : Choco installed? $chocoinstalled"

# Test Firewall
$DomainProfile = Get-NetFirewallProfile -Profile Domain
$PublicProfile = Get-NetFirewallProfile -Profile Public
$PrivateProfile = Get-NetFirewallProfile -Profile Private
$DomainProfile = $DomainProfile.Enabled
$PublicProfile = $PublicProfile.Enabled
$PrivateProfile = $PrivateProfile.Enabled
Logwrite "OUTPUT : Firewall : Domain Profile enabled? $DomainProfile"
Logwrite "OUTPUT : Firewall : Public Profile enabled? $PublicProfile"
Logwrite "OUTPUT : Firewall : Private Profile enabled? $PrivateProfile"

# Test UAC
$UACStatus = Get-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -ErrorAction SilentlyContinue
$UACStatus = $UACStatus.EnableLUA
if ($UACStatus = "0"){
    $UACEnabled = $False
    $UACEnabled
}
else {
    $UACEnabled = $True
    $UACEnabled

}
Logwrite "OUTPUT : UAC enabled? $UACEnabled"

# Test environment variables
$temp = [Environment]::GetEnvironmentVariable("TEMP")
$tmp = [Environment]::GetEnvironmentVariable("TMP")
Logwrite "OUTPUT : TMP environment variable is $tmp, TEMP is $temp"

# Test LS-SVR-Windows-LocalAdmins


# Test Volsup
$volsup = get-localuser -name volsup -ErrorAction SilentlyContinue
if ($volsup -ne $null){
    Logwrite "OUTPUT : VOLSUP was created"
}
else {
    Logwrite "OUTPUT : VOLSUP is missing"
}

# Test timezone
$timezone = Get-TimeZone | select StandardName
$timezone = $timezone.StandardName
Logwrite "OUTPUT : Timezone set to $timezone"

# Test Windows Features
$smb1state = Get-SmbServerConfiguration | Select EnableSMB1Protocol
$smb1state = $smb1state.EnableSMB1Protocol
$backupstate = Get-WindowsFeature Windows-Server-Backup
$backupstate = $backupstate.Installed
$admodulestate = Get-WindowsFeature RSAT-AD-PowerShell
$admodulestate = $admodulestate.Installed
Logwrite "OUTPUT : SMBv1 feature installed (should not be)? $smb1state"
Logwrite "OUTPUT : Windows Backup feature installed? $backupstate"
Logwrite "OUTPUT : AD PS Modules feature installed? $admodulestate"

#Test Windows Update
$WSUSGroup = Get-ItemProperty -Path HKLM:Software\Policies\Microsoft\Windows\WindowsUpdate -Name TargetGroup -ErrorAction SilentlyContinue
$WSUSGroup = $WSUSGroup.TargetGroup
$WSUSServer = Get-ItemProperty -Path HKLM:Software\Policies\Microsoft\Windows\WindowsUpdate -Name WUServer -ErrorAction SilentlyContinue
$WSUSServer= $WSUSServer.WUServer
Logwrite "OUTPUT : Windows Update server set to : $WSUSServer"
Logwrite "OUTPUT : Windows Update group set to : $WSUSGroup"
Logwrite "############"

#########################################################
# Build Completion                                     #
#########################################################
$instanceid = Invoke-WebRequest -uri http://169.254.169.254/latest/meta-data/instance-id
$instanceid = [string]$instanceid.content
$instancetype = Invoke-WebRequest -uri http://169.254.169.254/latest/meta-data/instance-type
$instancetype = [string]$instancetype.content
$hostname = hostname
$message = "New Instance/VM build sheet `n Hostname : ($hostname) `n Instance type : ($instancetype) `n Instance ID : ($instanceid)"
Publish-SNSMessage -TopicArn arn:aws:sns:ap-southeast-2:830074022218:WindowsBuilds -Message $message -Region ap-southeast-2


# Set build complete key
New-ItemProperty -Path HKLM:Software\DSGBuild -Name BuildComplete -PropertyType DWord -Value 1 -Force
LogWrite "INFO : Adding BuildComplete reg key"