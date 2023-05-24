<# 
.SYNOPSIS 
  Uninstall FusionInventory.
  Install GLPI Agent.
.DESCRIPTION 
  Uninstall FusionInventory.
  Install GLPI Agent.
.NOTES  
  File Name:  InstallGLPIAgent.ps1 
  Author:     Roberto Marcelino
  Requires:   PowerShell v5+
  Version:    2.1
#>

#=======================================================================================================================================
param (
  [string]$IsServer
)

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

#=======================================================================================================================================

$InstallServerPath = "\\<your_server>\netlogon"
$SetupTAG = ""<ENTITY>""

#=======================================================================================================================================

# GLPI-Agent version
$SetupVersion = "1.5-git1bd80d47"
$SetupServer = "https://<ADDRESS_OF_YOUR_SERVER>"
$hostname = [System.Net.Dns]::GetHostName().ToUpper()
$ServiceName = "glpi-agent"

if ([string]::IsNullOrEmpty($IsServer)) {
  $SetupOptions = "/quiet ADD_FIREWALL_EXCEPTION=1 DELAYTIME=60 EXECMODE=1 RUNNOW=1 SCAN_HOMEDIRS=1 SERVER=$SetupServer"
} else {
  $SetupOptions = "/quiet ADD_FIREWALL_EXCEPTION=1 ADDLOCAL=ALL DELAYTIME=60 EXECMODE=1 RUNNOW=1 SCAN_HOMEDIRS=1 SERVER=$SetupServer"
}

#=======================================================================================================================================
if ([System.Enum]::IsDefined([Net.SecurityProtocolType], "Tls12")) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} else {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
}

#=======================================================================================================================================
$SetupInstallDir = if ([System.Environment]::Is64BitOperatingSystem) {
    ${env:ProgramFiles}
  } else {
    ${env:ProgramFiles(x86)}
  }

$regkeyFusion = if (Test-Path -Path "HKLM:\SOFTWARE\Wow6432Node\FusionInventory-Agent") {
    "HKLM:\SOFTWARE\Wow6432Node\FusionInventory-Agent"
  } else {
    "HKLM:\SOFTWARE\FusionInventory-Agent"
  }

if (Test-Path "$SetupInstallDir\FusionInventory-Agent\Uninstall.exe") {
  Start-Process -FilePath "$SetupInstallDir\FusionInventory-Agent\Uninstall.exe" -ArgumentList "/S" -WorkingDirectory "$SetupInstallDir\FusionInventory-Agent" -Wait
}

if (-not [string]::IsNullOrEmpty($regkeyFusion)) {
  Remove-Item -Path $regkeyFusion -Force -ErrorAction SilentlyContinue
}

#=======================================================================================================================================
function DeleteService([string] $ServiceName) {
  Get-CimInstance -Class Win32_Service -Filter "Name='$ServiceName'" | ForEach-Object {
    $_.Delete()
  }
}

#=======================================================================================================================================
function Stop-ProcessOrService {
  param(
    [parameter(Mandatory=$true)]
    [string]$processName,
    [int]$timeout = 3
  )
  # Get all processes with the specified name.
  $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
  # Close the main window of each process.
  foreach ($process in $processes) {
    if (!$process.HasExited) {
      $process.CloseMainWindow() | Out-Null
    }
  }
  # Wait for the processes to exit.
  for ($i = 0; $i -le $timeout; $i++) {
    $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue | Where-Object { !$_.HasExited }
    if ($processes.Count -eq 0) {
      break
    }
    Start-Sleep 1
  }
  # If any processes are still running, force them to stop.
  $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue | Where-Object { !$_.HasExited }
  if ($processes.Count -gt 0) {
    foreach ($process in $processes) {
      Stop-Process -Id $process.Id -Force -ErrorAction Stop
    }
  }
  # Get all services with the specified name.
  $service = Get-Service -Name $processName -ErrorAction SilentlyContinue
  # Stop any services that are running.
  if ($service -ne $null) {
    if ($service.Status -eq 'Running') {
      Stop-Service -Name $processName -Force -ErrorAction SilentlyContinue
    }
  }
}

#=======================================================================================================================================
function Get-InstalledPath {
  param(
    [string]$productName = "GLPI-Agent"
  )
  $localPath = if ([Environment]::Is64BitOperatingSystem) { "${env:ProgramFiles}\$productName" } else { "${env:ProgramFiles(x86)}\$productName" }
  if (Test-Path -Path "${env:ProgramFiles}\$productName") {
    $InstalledPath = "${env:ProgramFiles}\$productName"
  } elseif (Test-Path -Path "${env:ProgramFiles(x86)}\$productName") {
    $InstalledPath = "${env:ProgramFiles(x86)}\$productName"
    }
  if (-not [string]::IsNullOrEmpty($InstalledPath)) {
        return $InstalledPath
    } else {
    return $localPath
  }
}

#=======================================================================================================================================
function Get-InstalledVersion {
  $installedVersion = "1.0"
    if (Test-Path -Path 'HKLM:\SOFTWARE\Wow6432Node\GLPI-Agent\Installer') { 
        $installedVersion = (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Wow6432Node\GLPI-Agent\Installer' -Name 'Version') -as [string]
    } elseif (Test-Path -Path 'HKLM:\SOFTWARE\GLPI-Agent\Installer') {
        $installedVersion = (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\GLPI-Agent\Installer' -Name 'Version') -as [string]
    }
    if ([string]::IsNullOrEmpty($installedVersion)) {
        $installedVersion = "1.0"
    }
    return $installedVersion
}

#=======================================================================================================================================
function Uninstall-GLPI-Agent {
  param(
    [string]$productName = "GLPI-Agent"
  )
  # Check if the product is installed.
  $installPath = Get-InstalledPath -productName $productName
  if (-not $installPath) {
    return
  }
  # Stop the GLPI-Agent service.
  Stop-ProcessOrService -processName glpi-agent
  # Check if the uninstall program exists.
  $uninstallExe = Join-Path $installPath "uninstall.exe"
  if (Test-Path $uninstallExe) {
    Start-Process -FilePath $uninstallExe -ArgumentList "/S" -WorkingDirectory $installPath -Wait | Out-Null
    return
  }
  # Get the uninstall string from the registry.
  $uninstallString = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" `
    | Get-ItemProperty `
    | Where-Object { $_.DisplayName -match "GLPI" } `
    | Select-Object -ExpandProperty UninstallString
  # Check if the uninstall string is not empty.
  if (-not [string]::IsNullOrEmpty($uninstallString)) {
    $uninstallArgs = ($uninstallString -split ' ')[1] -replace '/I', '/X'
    $uninstallArgs += " /quiet"
    Start-Process -FilePath "$env:SystemRoot\system32\msiexec.exe" -ArgumentList $uninstallArgs -Wait | Out-Null
    # Remove the product's registry entries.
    Remove-Item -Path "HKLM:\SOFTWARE\$productName" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\$productName" -Force -Recurse -ErrorAction SilentlyContinue
    # Remove the product's installation directory.
    Remove-Item -Path $installPath -Force -Recurse -ErrorAction SilentlyContinue
  }
}

#=======================================================================================================================================
function Install-GLPI-Agent {
    [alias('Install-GLPIAgent')]
    param (
        [Parameter(Mandatory = $true)][string] $InstalledVersion,
        [Parameter(Mandatory = $true)][string] $SetupVersion,
        [Parameter(Mandatory = $true)][string] $SetupOptions,
        [Parameter(Mandatory = $true)][string] $InstallServerPath,
        [Parameter(Mandatory = $true)][string] $SetupTAG
  )
  if ([string]::IsNullOrEmpty($InstalledVersion) -or ($InstalledVersion -ne $SetupVersion)) {
    $OperatingSystemArchitecture = if ([System.Environment]::Is64BitOperatingSystem) {
        "x64"
      } else {
        "x86"
      }
    $installerPath = Join-Path -Path $InstallServerPath -ChildPath "GLPI-Agent-$SetupVersion-$OperatingSystemArchitecture.msi"

    $msiExecArgs = "/i $installerPath $SetupOptions TAG=$SetupTAG"
    Start-Process -FilePath "$env:SystemRoot\system32\msiexec.exe" -ArgumentList $msiExecArgs -Wait | Out-Null
    
    $InstalledVersion = Get-InstalledVersion
    
    if ([string]::IsNullOrEmpty($InstalledVersion) -or ($InstalledVersion -ne $SetupVersion)) {
      Uninstall-GLPI-Agent
      Start-Process -FilePath "$env:SystemRoot\system32\msiexec.exe" -ArgumentList $msiExecArgs -Wait | Out-Null
    }
  }
}

#=======================================================================================================================================
function Set-ServiceRecovery {
  [alias('Set-Recovery')]
  param (
    [string] [Parameter(Mandatory=$true)] $ServiceDisplayName,
    [string] [Parameter(Mandatory=$true)] $Server,
    [string] $action1 = "restart",
    [int] $time1 = 120000, # in milliseconds
    [string] $action2 = "restart",
    [int] $time2 = 120000, # in milliseconds
    [string] $actionLast = "restart",
    [int] $timeLast = 120000, # in milliseconds
    [int] $resetCounter = 4000 # in seconds
  )
  Get-CimInstance -Class Win32_Service -ComputerName $Server | Where-Object {$_.DisplayName -imatch $ServiceDisplayName} | ForEach-Object {
    $action = "$action1/$time1/$action2/$time2/$actionLast/$timeLast"
    $output = & sc.exe "\\$Server" failure $($_.Name) actions=$action reset=$resetCounter
  }
}

#=======================================================================================================================================
if (Test-Path -Path "$SetupInstallDir\GLPI-Agent\perl") {
    $InstalledVersion = Get-InstalledVersion
    Stop-ProcessOrService -processName glpi-agent
} else {
    $InstalledVersion = "1.0"
}

$mpPreference = Get-MpPreference
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

try {
    Install-GLPI-Agent -InstalledVersion $InstalledVersion -SetupVersion $SetupVersion -SetupOptions $SetupOptions -InstallServerPath $InstallServerPath -SetupTAG $SetupTAG
} finally {
    Set-MpPreference -DisableRealtimeMonitoring $mpPreference.DisableRealtimeMonitoring -ErrorAction SilentlyContinue
}

if (Test-Path -Path "$SetupInstallDir\GLPI-Agent\perl") {
    Start-Service "glpi-agent"
}

#=======================================================================================================================================

Set-ServiceRecovery -ServiceDisplayName $servicename -Server $hostname

[System.GC]::Collect()
Get-Variable | Where-Object { $_.Name -notlike 'Microsoft.PowerShell.*' -and $_.Name -notlike '_' } | Remove-Variable -ErrorAction SilentlyContinue

#=======================================================================================================================================
