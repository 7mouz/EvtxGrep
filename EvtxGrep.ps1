<#
.SYNOPSIS
Grep for Windows Event Logs – search .evtx files.

.DESCRIPTION
A PowerShell tool to search through hundreds of .evtx files without clicking through Event Viewer.
Use it interactively or from the command line. Filter by date, Event ID, case, or go deep into XML.

.PARAMETER Path
Path to directory containing .evtx files. Defaults to current directory.

.PARAMETER SearchTerms
One or more search terms to find in event logs.
Example: -SearchTerms "WannaCry","malware","suspicious"

.PARAMETER CaseSensitive
Perform case-sensitive search. Default is case-insensitive.

.PARAMETER DeepSearch
Search all XML fields in addition to the Message field. More thorough but slower.

.PARAMETER StartDate
Filter events from this date forward. Format: MM/DD/YYYY

.PARAMETER EndDate
Filter events up to this date. Format: MM/DD/YYYY

.PARAMETER EventIds
Filter by specific Event IDs. Example: -EventIds 4624,4625,4688

.PARAMETER Output
Output format: GridView, CSV, TXT, Console, or All. Default: GridView

.PARAMETER OutputPath
Directory where CSV/TXT files will be saved. Defaults to Desktop or current directory.

.EXAMPLE
.\EvtxGrep.ps1
Run interactively – perfect when you don't want to remember parameters.

.EXAMPLE
.\EvtxGrep.ps1 -SearchTerms "ransomware"
Quick search for "ransomware" in the current folder, shows results in GridView

.EXAMPLE
.\EvtxGrep.ps1 -SearchTerms "WannaCry","malware" -Output CSV
Search multiple terms and export to a timestamped CSV file.

.EXAMPLE
.\EvtxGrep.ps1 -SearchTerms "error" -StartDate "01/01/2026" -EndDate "02/09/2026"
Only show errors from January to February 2026.

.EXAMPLE
.\EvtxGrep.ps1 -SearchTerms "logon" -EventIds 4624,4625 -Output All
Search specific Event IDs and output to all formats.

.EXAMPLE
.\EvtxGrep.ps1 -Path "C:\Logs" -SearchTerms "suspicious" -CaseSensitive -DeepSearch
Advanced search with case-sensitivity and deep XML searching.

.NOTES
Author: 7mouz
Version: 1.1
Requires: PowerShell 5.0+

.LINK
https://github.com/7mouz/EvtxGrep
#>

param(
    [ValidateScript({
        if ($_ -and -not (Test-Path $_ -PathType Container)) {
            throw "Path '$_' does not exist or is not a directory."
        }
        $true
    })]
    [string]$Path,
    
    [string[]]$SearchTerms,
    
    [switch]$CaseSensitive,
    
    [switch]$DeepSearch,
    
    [datetime]$StartDate,
    
    [datetime]$EndDate,
    
    [ValidateScript({
        foreach ($id in $_) {
            if ($id -lt 0 -or $id -gt 65535) {
                throw "Event ID '$id' is invalid. Must be between 0 and 65535."
            }
        }
        $true
    })]
    [int[]]$EventIds,
    
    [ValidateSet('GridView','CSV','TXT','Console','All')]
    [string]$Output,
    
    [ValidateScript({
        if ($_ -and -not (Test-Path $_ -PathType Container)) {
            throw "Output path '$_' does not exist or is not a directory."
        }
        $true
    })]
    [string]$OutputPath
)

# Set defaults
if (-not $Output) { $Output = 'GridView' }
if (-not $StartDate) { $StartDate = [datetime]::MinValue }
if (-not $EndDate) { $EndDate = [datetime]::MaxValue }
if (-not $EventIds) { $EventIds = @() }

# Check for help flags
if ($args -contains '-help' -or $args -contains '--help' -or $args -contains '/help') {
    Write-Host "`n=== EvtxGrep - Quick Help ===" -ForegroundColor Cyan
    Write-Host "`nINTERACTIVE MODE:" -ForegroundColor Green
    Write-Host "  .\EvtxGrep.ps1"
    Write-Host "`nCOMMAND-LINE EXAMPLES:" -ForegroundColor Green
    Write-Host "  .\EvtxGrep.ps1 -SearchTerms `"WannaCry`""
    Write-Host "  .\EvtxGrep.ps1 -SearchTerms `"WannaCry`",`"malware`" -Output CSV"
    Write-Host "  .\EvtxGrep.ps1 -SearchTerms `"error`" -StartDate `"01/01/2024`" -EndDate `"02/09/2024`""
    Write-Host "  .\EvtxGrep.ps1 -SearchTerms `"logon`" -EventIds 4624,4625"
    Write-Host "  .\EvtxGrep.ps1 -Path `"C:\Logs`" -SearchTerms `"suspicious`" -CaseSensitive -DeepSearch -Output All"
    Write-Host "`nFOR FULL HELP:" -ForegroundColor Green
    Write-Host "  Get-Help .\EvtxGrep.ps1 -Full"
    Write-Host ""
    exit
}

function Search-EventLogs {
    param(
        [string]$LogPath,
        [string[]]$Terms,
        [bool]$CaseSensitiveSearch,
        [bool]$DeepSearchMode,
        [datetime]$FilterStartDate,
        [datetime]$FilterEndDate,
        [int[]]$FilterEventIds,
        [string]$OutputFormat,
        [string]$OutputDirectory
    )
    
    Write-Host "`n================================================" -ForegroundColor Cyan
    Write-Host "          EvtxGrep - Event Log Scanner         " -ForegroundColor Cyan
    Write-Host "================================================`n" -ForegroundColor Cyan

    # Validate path exists
    if (-not (Test-Path $LogPath)) {
        Write-Host "[!] ERROR: Path does not exist: $LogPath" -ForegroundColor Red
        Write-Host "    Please verify the path and try again." -ForegroundColor Yellow
        return
    }

    # Find .evtx files
    try {
        $evtxFiles = Get-ChildItem $LogPath -Filter "*.evtx" -ErrorAction Stop
        $evtxCount = $evtxFiles.Count
    } catch {
        Write-Host "[!] ERROR: Unable to access directory: $LogPath" -ForegroundColor Red
        Write-Host "    $($_.Exception.Message)" -ForegroundColor Yellow
        return
    }
    
    if ($evtxCount -eq 0) {
        Write-Host "[!] ERROR: No .evtx files found in: $LogPath" -ForegroundColor Red
        Write-Host "    Please ensure the directory contains Windows Event Log files (.evtx)" -ForegroundColor Yellow
        return
    }

    Write-Host "[+] Found $evtxCount .evtx file(s) in: $LogPath" -ForegroundColor Green

    # Validate date range
    if ($FilterStartDate -ne [datetime]::MinValue -and $FilterEndDate -ne [datetime]::MaxValue) {
        if ($FilterStartDate -gt $FilterEndDate) {
            Write-Host "[!] ERROR: Start date cannot be after end date." -ForegroundColor Red
            Write-Host "    Start: $FilterStartDate" -ForegroundColor Yellow
            Write-Host "    End:   $FilterEndDate" -ForegroundColor Yellow
            return
        }
    }

    # Display search configuration
    Write-Host "`n================================================" -ForegroundColor Green
    Write-Host " Search Configuration" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "Log Path      : $LogPath" -ForegroundColor White
    Write-Host "Total Files   : $evtxCount" -ForegroundColor White
    Write-Host "Search Terms  : $($Terms -join ', ')" -ForegroundColor White
    Write-Host "Case Sensitive: $CaseSensitiveSearch" -ForegroundColor White
    Write-Host "Deep Search   : $DeepSearchMode" -ForegroundColor White
    if ($FilterStartDate -ne [datetime]::MinValue -or $FilterEndDate -ne [datetime]::MaxValue) {
        Write-Host "Date Range    : $(if($FilterStartDate -ne [datetime]::MinValue){$FilterStartDate.ToString('MM/dd/yyyy')}else{'Any'}) to $(if($FilterEndDate -ne [datetime]::MaxValue){$FilterEndDate.ToString('MM/dd/yyyy')}else{'Any'})" -ForegroundColor White
    }
    if ($FilterEventIds.Count -gt 0) {
        Write-Host "Event IDs     : $($FilterEventIds -join ', ')" -ForegroundColor White
    }
    Write-Host ""

    Write-Host "[*] Starting search...`n" -ForegroundColor Cyan
    
    # Initialize counters and results
    $results = @()
    $totalFiles = $evtxFiles.Count
    $currentFile = 0
    $errorCount = 0
    $emptyFileCount = 0
    $inaccessibleCount = 0

    foreach ($logFile in $evtxFiles) {
        $currentFile++
        $percentComplete = [math]::Round(($currentFile / $totalFiles) * 100)
        Write-Progress -Activity "Searching Event Logs" -Status "Processing: $($logFile.Name)" -PercentComplete $percentComplete
        
        Write-Host "[$currentFile/$totalFiles] Searching: $($logFile.Name)..." -ForegroundColor Yellow -NoNewline

        try {
            # Verify file still exists (handles OneDrive sync issues)
            if (-not (Test-Path $logFile.FullName)) {
                Write-Host " [SKIPPED - File moved/syncing]" -ForegroundColor Gray
                $inaccessibleCount++
                continue
            }



            # Try to read events from the log file
            $events = @(Get-WinEvent -Path $logFile.FullName -ErrorAction SilentlyContinue)

            
            # Check if file is empty
            if ($events.Count -eq 0) {
                Write-Host " [No events]" -ForegroundColor Gray
                $emptyFileCount++
                continue
            }

            # Filter events based on search criteria
            $filteredEvents = $events | Where-Object {
                $event = $_
                $xmlContent = $null
                
                # Apply Event ID filter
                if ($FilterEventIds.Count -gt 0 -and $event.Id -notin $FilterEventIds) {
                    return $false
                }
                
                # Apply date range filter
                if ($FilterStartDate -ne [datetime]::MinValue -and $event.TimeCreated -lt $FilterStartDate) {
                    return $false
                }
                if ($FilterEndDate -ne [datetime]::MaxValue -and $event.TimeCreated -gt $FilterEndDate) {
                    return $false
                }
                
                # Search for keywords in event data
                $matches = $false
                foreach ($term in $Terms) {
                    if ($DeepSearchMode) {
                        # Deep search: check both Message and full XML
                        try {
                            if (-not $xmlContent) {
                                $xmlContent = $event.ToXml()
                            }
                            
                            if ($CaseSensitiveSearch) {
                                if ($xmlContent -cmatch [regex]::Escape($term) -or 
                                    ($event.Message -and $event.Message -cmatch [regex]::Escape($term))) {
                                    $matches = $true
                                    break
                                }
                            } else {
                                if ($xmlContent -match [regex]::Escape($term) -or 
                                    ($event.Message -and $event.Message -match [regex]::Escape($term))) {
                                    $matches = $true
                                    break
                                }
                            }
                        } catch {
                            # Skip events that can't be converted to XML
                            continue
                        }
                    } else {
                        # Quick search: check Message field only
                        try {
                            if ($event.Message) {
                                if ($CaseSensitiveSearch) {
                                    if ($event.Message -cmatch [regex]::Escape($term)) {
                                        $matches = $true
                                        break
                                    }
                                } else {
                                    if ($event.Message -match [regex]::Escape($term)) {
                                        $matches = $true
                                        break
                                    }
                                }
                            }
                        } catch {
                            continue
                        }
                    }
                }
                
                return $matches
            }
            
            # Add matches to results
            if ($filteredEvents -and $filteredEvents.Count -gt 0) {
                Write-Host " [FOUND $($filteredEvents.Count) match(es)]" -ForegroundColor Green
                $results += $filteredEvents | Select-Object TimeCreated, 
                    @{N='SourceLog';E={$_.LogName}},
                    @{N='SourceFile';E={$logFile.Name}},
                    @{N='FilePath';E={$logFile.FullName}},
                    Id,
                    LevelDisplayName,
                    @{N='MatchedTerms';E={
                        $msg = $_.Message
                        ($Terms | Where-Object { 
                            if ($msg) {
                                $msg -match [regex]::Escape($_)
                            }
                        }) -join ', '
                    }},
                    Message
            } else {
                Write-Host "" # Just newline, no status needed
            }
        }
        catch {
            Write-Host " [ERROR: $($_.Exception.Message)]" -ForegroundColor Red
            $errorCount++
        }
    }

    Write-Progress -Activity "Searching Event Logs" -Completed

    # Display search summary
    Write-Host "`n================================================" -ForegroundColor Green
    Write-Host " Search Complete" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "Files processed  : $totalFiles" -ForegroundColor White
    Write-Host "Total matches    : $($results.Count)" -ForegroundColor Cyan
    Write-Host "Empty files      : $emptyFileCount" -ForegroundColor Gray
    if ($inaccessibleCount -gt 0) {
        Write-Host "Inaccessible     : $inaccessibleCount (OneDrive sync/moved)" -ForegroundColor Yellow
    }
    if ($errorCount -gt 0) {
        Write-Host "Errors           : $errorCount (permission/corruption)" -ForegroundColor Red
    }
    
    if ($results.Count -eq 0) {
        Write-Host "`n[!] No matches found." -ForegroundColor Yellow
        if ($errorCount -gt 0) {
            Write-Host "    Note: Some files could not be read. Try running as Administrator." -ForegroundColor Yellow
        }
        return
    }

    # Sort results by timestamp
    $results = $results | Sort-Object TimeCreated

    # Determine output directory
    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        if (Test-Path $desktopPath) {
            $OutputDirectory = $desktopPath
        } else {
            $OutputDirectory = $PWD.Path
        }
    }

    # Output results in requested format(s)
    Write-Host ""
    try {
        switch ($OutputFormat) {
            'GridView' {
                Write-Host "[*] Opening GridView..." -ForegroundColor Cyan
                $results | Out-GridView -Title "EvtxGrep Results - $($Terms -join ', ')"
            }
            'CSV' {
                $csvPath = Join-Path $OutputDirectory "EvtxGrep_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                $results | Export-Csv -Path $csvPath -NoTypeInformation -ErrorAction Stop
                Write-Host "[+] CSV exported to: $csvPath" -ForegroundColor Green
            }
            'TXT' {
                $txtPath = Join-Path $OutputDirectory "EvtxGrep_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                $results | Format-List | Out-File -FilePath $txtPath -ErrorAction Stop
                Write-Host "[+] TXT exported to: $txtPath" -ForegroundColor Green
            }
            'Console' {
                $results | Format-List | More
            }
            'All' {
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                $csvPath = Join-Path $OutputDirectory "EvtxGrep_$timestamp.csv"
                $txtPath = Join-Path $OutputDirectory "EvtxGrep_$timestamp.txt"
                
                $results | Export-Csv -Path $csvPath -NoTypeInformation -ErrorAction Stop
                $results | Format-List | Out-File -FilePath $txtPath -ErrorAction Stop
                $results | Out-GridView -Title "EvtxGrep Results - $($Terms -join ', ')"
                
                Write-Host "[+] CSV exported to: $csvPath" -ForegroundColor Green
                Write-Host "[+] TXT exported to: $txtPath" -ForegroundColor Green
                Write-Host "[+] GridView opened" -ForegroundColor Green
            }
        }
    } catch [System.UnauthorizedAccessException] {
        Write-Host "[!] ERROR: Access denied to output directory: $OutputDirectory" -ForegroundColor Red
        Write-Host "    Please check permissions or choose a different output path." -ForegroundColor Yellow
    } catch {
        Write-Host "[!] ERROR: Failed to save output files." -ForegroundColor Red
        Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Display breakdown by source file
    Write-Host "`n[*] Matches by log file:" -ForegroundColor Cyan
    $results | Group-Object SourceFile | Sort-Object Count -Descending | ForEach-Object {
        Write-Host "    $($_.Name): $($_.Count) matches" -ForegroundColor White
    }
    
    Write-Host "`n[*] Search completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
}

function Start-InteractiveMode {
    Write-Host "`n================================================" -ForegroundColor Cyan
    Write-Host "      EvtxGrep - Interactive Mode            " -ForegroundColor Cyan
    Write-Host "================================================`n" -ForegroundColor Cyan

    # Path selection
    Write-Host "[?] Select log file location:" -ForegroundColor Yellow
    Write-Host "    1. Use current directory: $PWD" -ForegroundColor Gray
    Write-Host "    2. Enter custom path" -ForegroundColor Gray
    $pathChoice = Read-Host "Choose option (1/2)"

    $LogPath = switch ($pathChoice) {
        '1' { $PWD.Path }
        '2' {
            Write-Host "`nEnter full path to .evtx files:" -ForegroundColor Yellow
            $customPath = Read-Host
            if ([string]::IsNullOrWhiteSpace($customPath)) {
                Write-Host "[!] No path provided. Using current directory." -ForegroundColor Red
                $PWD.Path
            } elseif (-not (Test-Path $customPath)) {
                Write-Host "[!] Path does not exist. Using current directory." -ForegroundColor Red
                $PWD.Path
            } else {
                $customPath
            }
        }
        default {
            Write-Host "[!] Invalid choice. Using current directory." -ForegroundColor Red
            $PWD.Path
        }
    }

    # Get search terms
    Write-Host "`n[?] Enter search terms (comma-separated):" -ForegroundColor Yellow
    Write-Host "    Examples: WannaCry,kali,192.168.1.1,malware,suspicious" -ForegroundColor Gray
    $searchInput = Read-Host "Search terms"
    
    if ([string]::IsNullOrWhiteSpace($searchInput)) {
        Write-Host "[!] No search terms provided. Exiting." -ForegroundColor Red
        return
    }

    $searchTerms = $searchInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    
    if ($searchTerms.Count -eq 0) {
        Write-Host "[!] No valid search terms. Exiting." -ForegroundColor Red
        return
    }
    
    # Search options
    Write-Host "`n[?] Case-sensitive search? (y/N):" -ForegroundColor Yellow
    $caseSensitive = (Read-Host).ToLower() -eq 'y'
    
    Write-Host "`n[?] Search options:" -ForegroundColor Yellow
    Write-Host "    1. Quick search (Message field only - FAST)" -ForegroundColor Gray
    Write-Host "    2. Deep search (All XML fields - SLOW)" -ForegroundColor Gray
    $searchDepth = Read-Host "Choose option (1/2)"
    $deepSearch = $searchDepth -eq '2'

    # Date range filter
    Write-Host "`n[?] Filter by date range? (y/N):" -ForegroundColor Yellow
    $useDateFilter = (Read-Host).ToLower() -eq 'y'
    
    $startDate = [datetime]::MinValue
    $endDate = [datetime]::MaxValue
    if ($useDateFilter) {
        $validStartDate = $false
        while (-not $validStartDate) {
            Write-Host "Start date (MM/DD/YYYY) or press Enter for no limit:" -ForegroundColor Yellow
            $startInput = Read-Host
            if ([string]::IsNullOrWhiteSpace($startInput)) {
                $validStartDate = $true
            } else {
                try {
                    $startDate = [DateTime]::Parse($startInput)
                    $validStartDate = $true
                } catch {
                    Write-Host "[!] Invalid date format. Please use MM/DD/YYYY" -ForegroundColor Red
                }
            }
        }
        
        $validEndDate = $false
        while (-not $validEndDate) {
            Write-Host "End date (MM/DD/YYYY) or press Enter for no limit:" -ForegroundColor Yellow
            $endInput = Read-Host
            if ([string]::IsNullOrWhiteSpace($endInput)) {
                $validEndDate = $true
            } else {
                try {
                    $tempEndDate = [DateTime]::Parse($endInput)
                    if ($startDate -ne [datetime]::MinValue -and $tempEndDate -lt $startDate) {
                        Write-Host "[!] End date cannot be before start date. Please try again." -ForegroundColor Red
                    } else {
                        $endDate = $tempEndDate
                        $validEndDate = $true
                    }
                } catch {
                    Write-Host "[!] Invalid date format. Please use MM/DD/YYYY" -ForegroundColor Red
                }
            }
        }
    }

    # Event ID filter
    Write-Host "`n[?] Filter by Event IDs? (y/N):" -ForegroundColor Yellow
    $useEventIdFilter = (Read-Host).ToLower() -eq 'y'
    
    $eventIds = @()
    if ($useEventIdFilter) {
        $validEventIds = $false
        while (-not $validEventIds) {
            Write-Host "Enter Event IDs (comma-separated, e.g. 4688,4689,59,60):" -ForegroundColor Yellow
            $eventIdInput = Read-Host
            if ([string]::IsNullOrWhiteSpace($eventIdInput)) {
                $validEventIds = $true
            } else {
                try {
                    $eventIds = $eventIdInput -split ',' | ForEach-Object { 
                        $id = [int]$_.Trim()
                        if ($id -lt 0 -or $id -gt 65535) {
                            throw "Event ID must be between 0 and 65535"
                        }
                        $id
                    }
                    $validEventIds = $true
                } catch {
                    Write-Host "[!] Invalid Event IDs. Use numbers between 0-65535" -ForegroundColor Red
                }
            }
        }
    }

    # Output options
    Write-Host "`n[?] Output format:" -ForegroundColor Yellow
    Write-Host "    1. GridView (interactive table)" -ForegroundColor Gray
    Write-Host "    2. Export to CSV" -ForegroundColor Gray
    Write-Host "    3. Export to TXT" -ForegroundColor Gray
    Write-Host "    4. Display in console" -ForegroundColor Gray
    Write-Host "    5. All of the above" -ForegroundColor Gray
    $outputChoice = Read-Host "Choose option (1-5)"

    $outputFormat = switch ($outputChoice) {
        '1' { 'GridView' }
        '2' { 'CSV' }
        '3' { 'TXT' }
        '4' { 'Console' }
        '5' { 'All' }
        default { 
            Write-Host "[!] Invalid choice. Using GridView." -ForegroundColor Yellow
            'GridView' 
        }
    }

    Write-Host "`nPress Enter to start search or Ctrl+C to cancel..." -ForegroundColor Yellow
    Read-Host

    # Execute search
    Search-EventLogs -LogPath $LogPath -Terms $searchTerms -CaseSensitiveSearch $caseSensitive `
                     -DeepSearchMode $deepSearch -FilterStartDate $startDate -FilterEndDate $endDate `
                     -FilterEventIds $eventIds -OutputFormat $outputFormat -OutputDirectory $null
}

# Main execution logic
if ($SearchTerms -ne $null -and $SearchTerms.Count -gt 0) {
    # Command-line mode
    $searchPath = if ([string]::IsNullOrWhiteSpace($Path)) { $PWD.Path } else { $Path }
    Search-EventLogs -LogPath $searchPath -Terms $SearchTerms -CaseSensitiveSearch $CaseSensitive.IsPresent `
                     -DeepSearchMode $DeepSearch.IsPresent -FilterStartDate $StartDate -FilterEndDate $EndDate `
                     -FilterEventIds $EventIds -OutputFormat $Output -OutputDirectory $OutputPath
} else {
    # Interactive mode
    Start-InteractiveMode
    
    # Keep window open if double-clicked
    if ($Host.Name -eq "ConsoleHost") {
        Write-Host "`nPress ENTER to exit..." -ForegroundColor Gray
        Read-Host | Out-Null
    }
}