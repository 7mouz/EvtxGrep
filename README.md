# EvtxGrep

> grep for Windows Event Logs

A PowerShell tool for searching and analyzing Windows Event Logs (.evtx files) with advanced filtering capabilities. Perfect for incident response, threat hunting, and forensic investigations.

##  Features

-  **Batch Processing** - Search multiple .evtx files simultaneously
-  **Flexible Search** - Multiple search terms, case-sensitive options, deep XML search
-  **Smart Filtering** - Filter by date range and Event IDs
-  **Multiple Outputs** - GridView, CSV, TXT, or all formats at once
-  **Dual Modes** - Interactive menu or command-line automation
-  **Built for Scale** - Process hundreds of files in minutes

##  Prerequisites

- Windows PowerShell 5.0 or higher
- Administrator rights (for some event logs)

##  Installation

1. Download `EvtxGrep.ps1`
2. Set execution policy (one-time setup):
```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

##  Usage

### Interactive Mode
```powershell
.\EvtxGrep.ps1
```

### Command-Line Mode

**Basic search:**
```powershell
.\EvtxGrep.ps1 -SearchTerms "ransomware"
```

**Multiple terms:**
```powershell
.\EvtxGrep.ps1 -SearchTerms "WannaCry","malware","suspicious" -Output CSV
```

**With date filtering:**
```powershell
.\EvtxGrep.ps1 -SearchTerms "error" -StartDate "01/01/2024" -EndDate "02/09/2024"
```

**Filter by Event IDs:**
```powershell
.\EvtxGrep.ps1 -SearchTerms "logon" -EventIds 4624,4625 -Output All
```

**Advanced search:**
```powershell
.\EvtxGrep.ps1 -Path "C:\Logs" -SearchTerms "suspicious" -CaseSensitive -DeepSearch -Output CSV
```

### Get Help
```powershell
.\EvtxGrep.ps1 -help
Get-Help .\EvtxGrep.ps1 -Full
```

##  Use Cases

- **Incident Response** - Quickly search across collected event logs from multiple systems
- **Threat Hunting** - Find indicators of compromise across server farms
- **Forensic Analysis** - Search for specific keywords in evidence files
- **Compliance Auditing** - Filter and export specific events for review
- **Security Monitoring** - Automate daily searches for suspicious activity
- **CTF & Forensics Challenges** - Rapidly find flags and artifacts

##  Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-SearchTerms` | Terms to search for | `-SearchTerms "WannaCry","malware"` |
| `-Path` | Directory with .evtx files | `-Path "C:\Logs"` |
| `-CaseSensitive` | Case-sensitive search | `-CaseSensitive` |
| `-DeepSearch` | Search XML fields (slower) | `-DeepSearch` |
| `-StartDate` | Filter from date | `-StartDate "01/01/2024"` |
| `-EndDate` | Filter to date | `-EndDate "02/09/2024"` |
| `-EventIds` | Filter by Event IDs | `-EventIds 4624,4625` |
| `-Output` | Output format | `-Output CSV` |
| `-OutputPath` | Save location | `-OutputPath "C:\Reports"` |

##  Why Not Event Viewer?

**Event Viewer is great for browsing one file at a time.**  
**EvtxGrep is for when you need to:**

-  Search 10, 50, 100+ event log files at once
-  Find needles in haystacks across multiple systems
-  Export filtered results for analysis
-  Automate recurring searches
-  Complex filtering (dates + Event IDs + keywords)

**Example:** Investigating ransomware across 50 servers?  
Event Viewer: ~3 hours of manual work  
EvtxGrep: `.\EvtxGrep.ps1 -SearchTerms "vssadmin","bcdedit" -Output CSV` → 2 minutes 

##  Security Note

This script:
-  Only reads .evtx files (no system modification)
-  Does not require internet connection
-  Does not collect or transmit data
-  All code is visible and reviewable
-  No external dependencies

## Common Event IDs for Threat Hunting

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4688 | Process creation |
| 4697 | Service installation |
| 7045 | Service installation (System log) |
| 1102 | Audit log cleared |

##  License

MIT License - see [LICENSE](LICENSE) file

##  Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

##  Author
**7mouz**


- GitHub: [@7mouz](https://github.com/7mouz)

##  Support

If you find this tool useful, please star the repository!

## Acknowledgments 

Inspired by real-world needs during forensics competitions and incident response engagements.

---

**Found a bug?** Open an issue  
**Have a feature request?** Open an issue  
**Want to contribute?** Submit a pull request