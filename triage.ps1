param(
    [Microsoft.ValidatedNotNullOrEmpty()]
    [ValidateScript({Test-Path $_ -IsValid})]
    [string]$Drive = "C:",
    [ValidateScript({Test-Path $_ -IsValid})]
    [string]$TargetSource = "C:",
    [ValidateSet("WinPMEM", "DumpIt")]
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

# Base output directory
$BaseOutputDir = "$Drive\Triage\$customIsoDateTime"

# Paths to external tools
$WinPMEMPath = "$Drive\Triage\WinPMEM\winpmem.exe"
$DumpItPath = "$Drive\Triage\DumpIT\DumpIt.exe"
$KAPEPath = "$Drive\Triage\KAPE\KAPE.exe"
$CyberTriagePath = "$Drive\Triage\CyberTriage\CyberTriageCollector.exe"
$HayabusaPath = "$Drive\Triage\Hayabusa\hayabusa.exe"
$HayabusaFolder = "$Drive\Triage\Hayabusa"
$TakajoPath = "$Drive\Triage\Takajo\takajo.exe"
$TakajoFolder = "$Drive\Triage\Takajo"
$ChainsawPath = "$Drive\Triage\Chainsaw\chainsaw.exe"
$ChainsawFolder = "$Drive\Triage\Chainsaw"


# Tool output directories
$MemoryDumpDir = "$BaseOutputDir\MemoryDumps"
$KAPEDir = "$BaseOutputDir\KAPE"
$CyberTriageOutputDir = "$BaseOutputDir\CyberTriage"
$HayabusaOutputDir = "$BaseOutputDir\Hayabusa"
$TakajoOutputDir = "$BaseOutputDir\Takajo"
$ChainsawOutputDir = "$BaseOutputDir\Chainsaw"


# Create output directories
try {
    if (!(Test-Path -Path $BaseOutputDir)) {New-Item -ItemType Directory -Path $BaseOutputDir -Force | Out-Null}
    if (!(Test-Path -Path $MemoryDumpDir)) {New-Item -ItemType Directory -Path $MemoryDumpDir -Force | Out-Null}
    if (!(Test-Path -Path $KAPEDir)) {New-Item -ItemType Directory -Path $KAPEDir -Force | Out-Null}
    if (!(Test-Path -Path $CyberTriageOutputDir)) {New-Item -ItemType Directory -Path $CyberTriageOutputDir -Force | Out-Null}
    if (!(Test-Path -Path $HayabusaOutputDir)) {New-Item -ItemType Directory -Path $HayabusaOutputDir -Force | Out-Null}
    if (!(Test-Path -Path $TakajoOutputDir)) {New-Item -ItemType Directory -Path $TakajoOutputDir -Force | Out-Null}
    if (!(Test-Path -Path $ChainsawOutputDir)) {New-Item -ItemType Directory -Path $ChainsawOutputDir -Force | Out-Null}

} catch {
    Write-Host "Error creating directories: $_" -ForegroundColor Red
    Exit
}

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "Info"
    )

    $logfile = "$BaseOutputDir\triage.log"
    
    if (!(Test-Path -Path $logfile)) {New-Item -ItemType File -Path $logfile}

    #$logfile = Join-Path "$BaseOutputDir\triage.log"

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    Add-Content -Path $logfile -Value $logMessage

    switch ($Level) {
        "Error" {
            Write-Host $logMessage -ForegroundColor Red
        }
        "Warning" {
            Write-Host $logMessage -ForegroundColor Yellow
        }
        default {
            Write-Host $logMessage
        }
    }
    
}
Write-Log "Starting triage process at: $customIsoDateTime" "Info"


function Test-RequiredTools {
    $tools = @{
        "WinPMEM" = $WinPMEMPath
        "DumpIt" = $DumpItPath
        "KAPE" = $KAPEPath
        "CyberTriage" = $CyberTriagePath
        "Hayabusa" = $HayabusaPath
        "Chainsaw" = $ChainsawPath
    }

    foreach ($tool in $tools.GetEnumerator()) {
        if (-not (Test-Path $tool.Value)) {
            Write-Log "Required tool not found: $($tool.Key)" "Error"-ForegroundColor Red
            return $false
        }
        return $true
    }
}

if (-not (Test-RequiredTools)) {
    Write-Host "One or more required tools are missing. Please ensure all required tools are present in the specified directory." -ForegroundColor Red
    Exit
}


function Show-Progess {
    param (
        [string]$Activity,
        [int]$PercentComplete
    )
    Write-Progress -Activity $Activity -PercentComplete $PercentComplete -Status "$PercentComplete% complete"
}

# Collect memory dump using WinPMEM or DumpIt
function Get-MemoryDump {
    param (
        [string]$Tool = $MemoryDumpTool
    )
    switch ($Tool) {
        "WinPMEM" {
            Write-Host "Collecting memory dump using WinPMEM..."
            Start-Process -FilePath $WinPMEMPath -ArgumentList "$MemoryDumpDir\memorydump_winpmem.raw" -Wait
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
function Start-KAPE {
    param (
        [string]$Source = $TargetSource
    )
    Write-Host "Running KAPE for artifact collection..."
    Start-Process -FilePath $KAPEPath -ArgumentList "--tsource $Source --tdest $KAPEDir --target ""!SANS_Triage""" -Wait
}

# Function to run Cyber Triage for analysis
function Start-CyberTriage {
    param (
        [string]$InputDir = $TargetSource
    )
    Write-Host "Running Cyber Triage..."
    Start-Process -FilePath $CyberTriagePath -ArgumentList "-o $CyberTriageOutputDir\Cybertriage-output" -Wait
}

# Function to run Hayabusa analysis
function Start-Hayabusa {
    param(
        [string]$OutputPath = $HayabusaOutputDir,
        [string]$LogPath = "$KAPEDir\C\Windows\System32\winevt\logs",
        [string]$HayaProfile = "standard",
        [switch]$LiveAnalysis,
        [switch]$SplitByLevel
    )

# Start-Hayabusa -OutputPath $HayabusaOutputDir -LiveAnalysis -SplitByLevel

    Write-Host "Running Hayabusa analysis..."
    
    $csvOutput = "$OutputPath\hayabusa_results.csv"
    #if (!(Test-Path -Path $csvOutput)) {New-Item -ItemType File -Path $csvOutput}
    $htmlOutput = "$OutputPath\hayabusa_report.html"
    #if (!(Test-Path -Path $htmlOutput)) {New-Item -ItemType File -Path $htmlOutput}
    $jsonOutput = "$OutputPath\hayabusa_report.jsonl"
    $jsonhtmlOutput = "$OutputPath\hayabusa_json_report.html"


    try {
        if ($LiveAnalysis) {
            #Start-Process -FilePath $HayabusaPath -ArgumentList "csv-timeline -l -o $csvOutput -H $htmlOutput -p $HayaProfile --no-wizard" -Wait
            Start-Process -FilePath $HayabusaPath -ArgumentList "csv-timeline -l --proven-rules --enable-unsupported-rules --visualize-timeline --remove-duplicate-data -o $csvOutput -H $htmlOutput -p $HayaProfile" -Wait
        }
        else {
            #Start-Process -FilePath $HayabusaPath -ArgumentList "csv-timeline -d $LogPath -o $csvOutput -H $htmlOutput -p $HayaProfile" -Wait
            # Add --EID-filter to Scan only common EIDs for faster speed
            Start-Process -FilePath $HayabusaPath -ArgumentList "csv-timeline -P -u -R -T -d $LogPath -o $csvOutput -H $htmlOutput -p $HayaProfile" -Wait
            Start-Process -FilePath $HayabusaPath -ArgumentList "json-timeline -P -u -R -d $LogPath -L -o $jsonOutput -p timesketch-verbose" -Wait
        }

        if (Test-Path $csvOutput) {
            Write-Host "Hayabusa analysis completed successfully. Results saved to: $csvOutput"
            Write-Host "HTML report saved to: $htmlOutput"
             
       if ($SplitByLevel) {
               $categoryDir = Join-Path $OutputPath "hayabusa_by_category"
                New-Item -ItemType Directory -Path $categoryDir -Force | Out-Null

                $criticalFile = Join-Path $categoryDir "critical_alerts.csv"
                $highFile = Join-Path $categoryDir "high_alerts.csv"
                $mediumFile = Join-Path $categoryDir "medium_alerts.csv"
                #$lowFile = Join-Path $categoryDir "low_alerts.csv"
                #$infoFile = Join-Path $categoryDir "informational_alerts.csv"
    
                $headers = (Get-Content $csvOutput -TotalCount 1).Split(',')
                $headerLine = $headers -join ','
    
                #@($criticalFile, $highFile, $mediumFile, $lowFile, $infoFile) | ForEach-Object {
                 #   Set-Content -Path $_ -Value $headerLine
                  #  }
                  @($criticalFile, $highFile, $mediumFile) | ForEach-Object {
                    Set-Content -Path $_ -Value $headerLine
                    }


                $reader = [System.IO.StreamReader]::new($csvOutput)
                $reader.ReadLine() # Skip header

                while (($line = $reader.ReadLine()) -ne $null) {
    
                        Write-Output "Line: " $line

                        if ($line.Contains("critical")) {
                        Add-Content -Path $criticalFile -Value $line 
                        }
                        elseif ($line.Contains("high")) {
                        Add-Content -Path $highFile -Value $line 
                        }
                        elseif ($line.Contains("med")) {
                        Add-Content -Path $mediumFile -Value $line 
                        }
                        #elseif ($line.Contains("low")) {
                        #Add-Content -Path $lowFile -Value $line 
                        #}
                        #elseif ($line.Contains("info")) {
                        #Add-Content -Path $infoFile -Value $line 
                        #}

                      }

                $reader.Close()
                Write-Host "Results have been categorized by severity level in: $categoryDir"
            }
        }
        }
        catch {
            Write-Host "Error running Hayabusa: $_"
              }
    
  }
  

# Function to run Takajo for automagic and HTML report generation
function Start-Takajo {
    param(
        [string]$OutputPath = $TakajoOutputDir,
        [string]$LogPath = "$KAPEDir\$Drive\Windows\System32\winevt\Logs",
        [string]$TakajoPath = "$Drive\Triage\Takajo\takajo.exe",
        [string]$HayabusaJsonlPath = "$BaseOutputDir\Hayabusa\hayabusa_report.jsonl"
    )

    Write-Host "Running Takajo automagic and HTML report generation..."
    $automagicOutput = Join-Path $OutputPath "takajo_automagic_results"
    # New-Item -ItemType Directory -Path $automagicOutput -Force | Out-Null
    $htmlReportOutput = Join-Path $OutputPath "takajo_report.html"
    $timelineReportOutput = Join-Path $OutputPath "takajo_timeline_susp_proc.csv"

    try {
        New-Item -ItemType Directory -Path $automagicOutput -Force | Out-Null

        Start-Process -FilePath $TakajoPath -ArgumentList "automagic --log $LogPath --output $automagicOutput --hayabusa $HayabusaJsonlPath" -Wait
        Start-Process -FilePath $TakajoPath -ArgumentList "html-report --log $LogPath --output $htmlReportOutput" -Wait
        Start-Process -FilePath $TakajoPath -ArgumentList "timeline-suspicious-processes -t $HayabusaJsonlPath -o $timelineReportOutput" -Wait

        if (Test-Path $automagicOutput) {
            Write-Host "Takajo automagic analysis completed successfully. Results saved to: $automagicOutput"
        }

        if (Test-Path $htmlReportOutput) {
            Write-Host "Takajo HTML report generated successfully. Report saved to: $htmlReportOutput"
        }
    }
    catch {
        Write-Host "Error running Takajo: $_"
    }
}

# Function to run DFIR Chainsaw
function Start-Chainsaw {
    param(
        [string]$OutputPath = $ChainsawOutputDir,
        [string]$LogPath = "$KAPEDir\C\Windows\System32\winevt\Logs",
        [string]$RulesPath = "$ChainsawFolder\rules",
        [string]$Sigma = "$ChainsawFolder\sigma",
        [int]$SplitByLevel = 0
    )

    Write-Host "Running DFIR Chainsaw analysis..."
    $chainsawOutput = Join-Path $OutputPath "chainsaw_results"
    $chainsawmapping = "$ChainsawFolder\mappings\sigma-event-logs-all.yml"
    
    try {
        New-Item -ItemType Directory -Path $chainsawOutput -Force | Out-Null

        Start-Process -FilePath $ChainsawPath -ArgumentList "hunt $LogPath --rule $RulesPath --sigma $Sigma --output $chainsawOutput --csv --full --mapping $chainsawmapping" -Wait

        if (Test-Path $chainsawOutput) {
            Write-Host "Chainsaw analysis completed successfully. Results saved to: $chainsawOutput"
            if ($SplitByLevel) {
                $categoryDir = Join-Path $OutputPath "chainsaw_by_level"
                New-Item -ItemType Directory -Path $categoryDir -Force | Out-Null

                Get-ChildItem -Path $chainsawOutput -Filter "*.csv" | ForEach-Object {
                    $results = Import-Csv $_.FullName

                    $results | Where-Object { $_.'Level' -eq 'Critical' } | 
                        Export-Csv -Path (Join-Path $categoryDir "critical_alerts.csv") -NoTypeInformation -Append
                    
                    $results | Where-Object { $_.'Level' -eq 'High' } | 
                        Export-Csv -Path (Join-Path $categoryDir "high_alerts.csv") -NoTypeInformation -Append
                    
                    $results | Where-Object { $_.'Level' -eq 'Info' } | 
                        Export-Csv -Path (Join-Path $categoryDir "info_alerts.csv") -NoTypeInformation -Append
                }

                Write-Host "Results have been categorized by severity level in: $categoryDir"
            }
        }
    }
    catch {
        Write-Host "Error running Chainsaw: $_"
    }
}

function Get-RDPAuthEvents {
    param (
        [string]$EvtxFilePath = "$KAPEDir\C\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"
    )

    if ($EvtxFilePath -ne "") {
        # Collect Event ID 1149 from the specified .evtx file
        $RDPAuths = Get-WinEvent -Path $EvtxFilePath -FilterXPath '<QueryList><Query Id="0"><Select>*[System[EventID=1149]]</Select></Query></QueryList>'
    } else {
        # Collect Event ID 1149 from live RemoteConnectionManager logs if a file is not available
        $RDPAuths = Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -FilterXPath '<QueryList><Query Id="0"><Select>*[System[EventID=1149]]</Select></Query></QueryList>'
    }

    # Extract relevant data into objects directly without converting to XML if possible
    $EventData = Foreach ($event in $RDPAuths) {
        [PSCustomObject]@{
            TimeCreated = (Get-Date ($event.TimeCreated) -Format 'yyyy-MM-dd hh:mm:ss K')
            User = [string]$event.Properties.Value[0]
            UserDomainName = [string]$event.Properties.Value[1] 
            SourceIP = [string]$event.Properties.Value[2]
            RDPAuthMessage = " Remote Desktop Services: User authentication succeeded"
        }
    }

    return $EventData
}

function Get-RDPLogonEvents {
    param (
        [string]$EvtxFilePath = "$KAPEDir\C\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"
    )

    if ($EvtxFilePath -ne "") {
        # Collect Event ID 1149 from the specified .evtx file
        $RDPLogons = Get-WinEvent -Path $EvtxFilePath -FilterXPath '<QueryList><Query Id="0"><Select>*[System[EventID=21]]</Select></Query></QueryList>'
    } else {
        # Collect Event ID 1149 from live RemoteConnectionManager logs if a file is not available
        $RDPLogons = Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -FilterXPath '<QueryList><Query Id="0"><Select>*[System[EventID=21]]</Select></Query></QueryList>'
    }

    # Extract relevant data into objects directly without converting to XML if possible
    $EventData = Foreach ($event in $RDPLogons) {
        [PSCustomObject]@{
            TimeCreated = (Get-Date ($event.TimeCreated) -Format 'yyyy-MM-dd hh:mm:ss K')
            User = [string]$event.Properties.Value[0]
            SessionID = [string]$event.Properties.Value[1]
            SourceIP = [string]$event.Properties.Value[2]
            RDPLogonMessage = " Remote Desktop Services: Session Logon succeeded"
        }
    }

    return $EventData
}

# Main 

try {
    
Write-Host "Starting triage at: $customIsoDateTime"
Write-Host "Output directory: $BaseOutputDir"

Show-Progess "Collecting Memory Dump" 20
Get-MemoryDump -Tool $MemoryDumpTool
Write-Log "Memory dump collection completed" "Info"

Show-Progess "Running KAPE" 40
Start-KAPE -Source $TargetSource
Write-Log "KAPE execution completed" "Info"

Show-Progess "Running Cyber Triage" 50
Start-CyberTriage -InputDir $TargetSource
Write-Log "Cyber Triage analysis completed" "Info"

Show-Progess "Running Hayabusa" 60
Start-Hayabusa -OutputPath $HayabusaOutputDir -SplitByLevel
Write-Log "Hayabusa analysis completed" "Info"

Show-Progess "Running Hayabusa" 70
Start-Takajo 
Write-Log "Takajo analysis completed" "Info"


Show-Progess "Running Chainsaw" 90
Start-Chainsaw -OutputPath $ChainsawOutputDir -SplitByLevel
Write-Log "Chainsaw analysis completed" "Info"

Show-Progess "Extracting RDP Authentication Events" 95
$RDPAuthEventData = Get-RDPAuthEvents -EvtxFilePath $evtxFilePath
$RDPAuthEventDataTable = $RDPAuthEventData | Format-Table
$RDPAuthEventDataTable | Out-File -FilePath "$BaseOutputDir\RDPAuthEvents.log" -Append
Write-Log "RDP Authentication events extraction completed" "Info"

Get-RDPLogonEvents

$FinishDateTime = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
Write-Host "Finished triage at: $FinishDateTime"
Write-Log "Finished triage at: $FinishDateTime" "Info"
Write-Log "All outputs are stored in: $BaseOutputDir" "Info"

Write-Host "Forensics triage completed successfully."
Write-Host "All outputs are stored in: $BaseOutputDir"

}
catch {
    Write-Log $_.Exception.Message "Error" exit 1
}
finally {
    Write-Progress -Activity "Triage process completed" -Completed
}
