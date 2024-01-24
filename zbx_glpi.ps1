<# 
.SYNOPSIS 
	Uninstall FusionInventory.
	Install GLPI Agent.
.DESCRIPTION 
	Uninstall FusionInventory.
	Install GLPI Agent.
.NOTES  
	File Name:  zbx_glpi.ps1 
	Author:     ISL Suporte Limitada
	Requires:   PowerShell v5
	Version:    2.5
#>

#=======================================================================================================================================

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

#=======================================================================================================================================

$InstallServerPath = "\\<your_server>\netlogon"
$SetupTAG = "<ENTITY>"

#=======================================================================================================================================

# GLPI-Agent version
$SetupVersion = "1.7"
$SetupServer = "https://<ADDRESS_OF_YOUR_SERVER>"
$hostname = [System.Net.Dns]::GetHostName().ToUpper()
$ServiceName = "glpi-agent"

#=======================================================================================================================================
function IsWindowsServer {
	if ($PSVersion -ge 3) {
		$os = Get-CimInstance -ClassName Win32_OperatingSystem
	} else {
		$os = Get-WmiObject -Class Win32_OperatingSystem
	}
	return $os.ProductType -ne 1  # True para servidores, False para estações de trabalho (clientes)
}

#=======================================================================================================================================

if (IsWindowsServer) {
	$SetupOptions = "/quiet ADD_FIREWALL_EXCEPTION=1 AGENTMONITOR=1 ADDLOCAL=ALL BACKEND_COLLECT_TIMEOUT=500 DELAYTIME=60 EXECMODE=2 NO_SSL_CHECK=1 RUNNOW=1 SCAN_HOMEDIRS=1 SERVER=$SetupServer/marketplace/glpiinventory/"
} else {
	$SetupOptions = "/quiet ADD_FIREWALL_EXCEPTION=1 ADDLOCAL=ALL BACKEND_COLLECT_TIMEOUT=500 DELAYTIME=60 EXECMODE=2 NO_SSL_CHECK=1 RUNNOW=1 SCAN_HOMEDIRS=1 SERVER=$SetupServer/marketplace/glpiinventory/"
}

#=======================================================================================================================================
$originalValue = [Net.ServicePointManager]::SecurityProtocol
if ([System.Enum]::IsDefined([Net.SecurityProtocolType], "Tls13")) {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13
} elseif ([System.Enum]::IsDefined([Net.SecurityProtocolType], "Tls12")) {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} else {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
}
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

#=======================================================================================================================================
$SetupInstallDir = if ($is64BitOS) { $env:ProgramFiles } else { $env:ProgramFilesX86 }

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
	$localPath = Join-Path -Path $SetupInstallDir -ChildPath $productName
	if (Test-Path -Path $localPath) {
		return $localPath
	} else {
		return $localPath
	}
}

#=======================================================================================================================================
function Get-InstalledVersion {
	$registryPaths = @(
		'HKLM:\SOFTWARE\Wow6432Node\GLPI-Agent\Installer',
		'HKLM:\SOFTWARE\GLPI-Agent\Installer'
	)
	$installedVersion = "1.0"
	foreach ($path in $registryPaths) {
		if (Test-Path -Path $path) {
			try {
				$property = Get-ItemProperty -Path $path
				$installedVersion = $property.Version -as [string]
				if (-not [string]::IsNullOrEmpty($installedVersion)) {
					break
				}
			}
			catch {
				Write-Warning "Um erro ocorreu ao recuperar a versão instalada de $path"
			}
		}
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
if (Test-Path -Path "$SetupInstallDir\GLPI-Agent\perl") {
    $InstalledVersion = Get-InstalledVersion
    Stop-ProcessOrService -processName glpi-agent
} else {
    $InstalledVersion = "1.0"
}

if ([Environment]::OSVersion.Version -ge (New-Object System.Version "10.0")) {
	if (-not (IsWindowsServer)) {
		$mpPreference = Get-MpPreference
		Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
	}
}

try {
    Install-GLPI-Agent -InstalledVersion $InstalledVersion -SetupVersion $SetupVersion -SetupOptions $SetupOptions -InstallServerPath $InstallServerPath -SetupTAG $SetupTAG
} finally {
	if ([Environment]::OSVersion.Version -ge (New-Object System.Version "10.0")) {
		if (-not (IsWindowsServer)) {
			Set-MpPreference -DisableRealtimeMonitoring $mpPreference.DisableRealtimeMonitoring -ErrorAction SilentlyContinue
		}
	}
}

#=======================================================================================================================================

[System.GC]::Collect()
Get-Variable | Where-Object { $_.Name -notlike 'Microsoft.PowerShell.*' -and $_.Name -notlike '_' } | Remove-Variable -ErrorAction SilentlyContinue

#=======================================================================================================================================
