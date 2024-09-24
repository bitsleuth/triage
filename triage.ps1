
param(
    [string]$Drive = "C:",
    [string]$TargetSource = "C:",
    [string]$MemoryDumpTool = "WinPMEM"
)

# Function to check for administrator privileges
function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Check for administrator privileges
if (-not (Test-Administrator)) {
    Write-Host "This script requires administrator privileges to run properly. Please restart PowerShell as an administrator." -ForegroundColor Red
    Exit
}

# Create timestamp variable
$customIsoDateTime = Get-Date -Format "yyyyMMddHHmmss"

# Define base output directory
$BaseOutputDir = "$Drive\Triage\$customIsoDateTime"

# Define paths to external tools
$WinPMEMPath = "$Drive\Triage\winpmem.exe"
$DumpItPath = "$Drive\Triage\DumpIt.exe"
$KAPEPath = "$Drive\Triage\KAPE.exe"
$CyberTriagePath = "$Drive\Triage\CyberTriageCLI.exe"

# Define output directories
$MemoryDumpDir = "$BaseOutputDir\MemoryDumps"
$KAPEDir = "$BaseOutputDir\KAPE"
$CyberTriageOutputDir = "$BaseOutputDir\CyberTriage\CyberTriage"

# Create output directories
New-Item -ItemType Directory -Path $BaseOutputDir -Force
New-Item -ItemType Directory -Path $MemoryDumpDir -Force
New-Item -ItemType Directory -Path $KAPEDir -Force
New-Item -ItemType Directory -Path $CyberTriageOutputDir -Force

# Function to collect memory dump using WinPMEM, DumpIt, or AdditionalDumpIt
function Collect-MemoryDump {
    param (
        [string]$Tool = "WinPMEM"
    )
    switch ($Tool) {
        "WinPMEM" {
            Write-Host "Collecting memory dump using WinPMEM..."
            Start-Process -FilePath $WinPMEMPath -ArgumentList "--output $MemoryDumpDir\memorydump_winpmem.raw" -Wait
        }
        "DumpIt" {
            Write-Host "Collecting memory dump using DumpIt..."
            Start-Process -FilePath $DumpItPath -ArgumentList "/Q /O $MemoryDumpDir\memorydump_dumpit.dmp" -Wait
        }
        default {
            Write-Host "Invalid tool specified. Please choose 'WinPMEM', or 'DumpIt'"
        }
    }
}

# Function to run KAPE for artifact collection
function Run-KAPE {
    param (
        [string]$Source = $TargetSource
    )
    Write-Host "Running KAPE for artifact collection..."
    #Start-Process -FilePath $KAPEPath -ArgumentList "--tsource $Source --tdest $KAPEDir --target ""WindowsDefender,Microsoft Teams,OneDrive,!SANS_Triage""" -Wait
    Start-Process -FilePath $KAPEPath -ArgumentList "--tsource $Source --tdest $KAPEDir --target ""!SANS_Triage""" -Wait
}

# Function to run Cyber Triage for analysis
function Run-CyberTriage {
    param (
        [string]$InputDir = $TargetSource
    )
    Write-Host "Running Cyber Triage..."
    Start-Process -FilePath $CyberTriagePath -ArgumentList "-o $CyberTriageOutputDir" -Wait
}

# Main execution flow
Write-Host "Starting triage at: $customIsoDateTime"
Write-Host "Output directory: $BaseOutputDir"

Collect-MemoryDump -Tool $MemoryDumpTool
Run-KAPE -Source $TargetSource
Run-CyberTriage -InputDir $TargetSource

$FinishDateTime = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"

Write-Host "Finished triage at: $FinishDateTime"
Write-Host "Forensics triage completed successfully."
Write-Host "All outputs are stored in: $BaseOutputDir"
