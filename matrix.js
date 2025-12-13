
// Global State
const TACTICS = [
  { id: "TA0043", name: "Reconnaissance" },
  { id: "TA0042", name: "Resource Development" },
  { id: "TA0001", name: "Initial Access" },
  { id: "TA0002", name: "Execution" },
  { id: "TA0003", name: "Persistence" },
  { id: "TA0004", name: "Privilege Escalation" },
  { id: "TA0005", name: "Defense Evasion" },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery" },
  { id: "TA0008", name: "Lateral Movement" },
  { id: "TA0009", name: "Collection" },
  { id: "TA0011", name: "Command and Control" },
  { id: "TA0010", name: "Exfiltration" },
  { id: "TA0040", name: "Impact" }
];

// --- DATA STRUCTURE FOR TECHNIQUES ---
// ADD YOUR TECHNIQUES HERE
// The key is the Tactic ID (e.g., TA0001). The value is an array of technique objects.
const TECHNIQUES = {

"TA0043": [
  {
    id: "T1046",
    name: "Port Scan",
    description: "Adversaries may scan systems to identify open ports and running services.",
    rules: [
      {
        type: "QRadar AQL",
        lang: "qradar",
        code: `SELECT sourceip, destinationip, UNIQUECOUNT(destinationport) AS ports_scanned, COUNT(*) AS event_count
FROM events
WHERE eventdirection IN ('R2L','R2R')
GROUP BY sourceip, destinationip
HAVING ports_scanned > 20 
LAST 5 MINUTES`
      },
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `CommonSecurityLog
| where TimeGenerated > ago(5m)
| summarize ports_scanned = dcount(DestinationPort) by SourceIP, DestinationIP
| where ports_scanned > 20`
      },
      {
        type: "Splunk SPL",
        lang: "splunk",
        code: `index=your_index earliest=-5m
| stats dc(dst_port) AS ports_scanned, count AS event_count BY src_ip dest_ip
| where ports_scanned > 20`
      }
    ]
  },

  {
    id: "T1018",
    name: "Network Scan",
    description: "Adversaries may scan the network to identify active hosts.",
    rules: [
      {
        type: "QRadar AQL",
        lang: "qradar",
        code: `SELECT sourceip, UNIQUECOUNT(destinationip) as hosts_scanned, COUNT(*) AS event_count
FROM events
Where eventdirection IN ('R2L','R2R')
GROUP BY sourceip
HAVING hosts_scanned > 20`
      },
	      {
	        type: "Sentinel KQL",
	        lang: "sentinel",
	        code: `CommonSecurityLog
	| where TimeGenerated > ago(5m)
	| summarize Host_Scanned = dcount(DestinationIP) by SourceIP
	| where Host_Scanned > 20`
	      },
	      {
	        type: "Splunk SPL",
	        lang: "splunk",
	        code: `index=* earliest=-5m
	| stats dc(dest_ip) AS hosts_scanned BY src_ip
	| where hosts_scanned > 20`
	      }
    ]
  },
  
  {
  "id": "T1046",
  "name": "Path Enumeration",
  "author": "Community",
  "description": "Detects enumeration of multiple unique URL paths from the same client, often used in web reconnaissance or forced browsing.",
  "siem_tags": ["Recon", "Web", "PathEnumeration"],
  "subtechniques": [],
  "rules": [
    {
      "lang": "kql",
      "type": "Sentinel - KQL",
      "code": "AzureDiagnostics\n| where isnotempty(requestUri_s)\n| summarize UniqueURIs = dcount(requestUri_s), URIs = make_set(requestUri_s, 200) by clientIp_s, hostname_s\n| where UniqueURIs > 30\n| project clientIp_s, hostname_s, UniqueURIs, URIs"
    },
    {
      "lang": "qradar",
      "type": "Qradar - AQL",
      "code": "SELECT sourceip, destinationip, UNIQUECOUNT(\"Request URI\") AS N_REQUEST\nFROM events\n WHERE destinationport IN (80, 443)\n  AND \"Request URI\" IS NOT NULL\n  AND \"Request URI\" != 'N/A'\n  AND eventdirection IN ('R2L', 'R2R')\nGROUP BY sourceip, destinationip\nHAVING N_REQUEST > 20"
    },
    {
      "lang": "splunk",
      "type": "Splunk",
      "code": "index=* http_method=POST\n| stats dc(uri_path) AS unique_paths, values(uri_path) AS paths BY src, dest\n| where unique_paths > 30\n| table _time src dest unique_paths paths\n| sort - unique_paths"
    }
  ]
},


{
  "id": "T1046",
  "name": "Web Host Enumeration",
  "author": "Community",
  "description": "Detects enumeration of multiple hostnames accessed from the same client IP, typical of web reconnaissance tools.",
  "siem_tags": ["Recon", "Web", "HostEnumeration"],
  "subtechniques": [],
  "rules": [
    {
      "lang": "kql",
      "type": "Sentinel - KQL",
      "code": "AzureDiagnostics\n| where isnotempty(hostname_s)\n| summarize UniqueHosts = dcount(hostname_s), Hosts = make_set(hostname_s, 200) by clientIp_s\n| where UniqueHosts > 20\n| project TimeGenerated, clientIp_s, UniqueHosts, Hosts"
    },
    {
      "lang": "qradar",
      "type": "Qradar - AQL",
      "code": "SELECT sourceip, UNIQUECOUNT(\"Host\") AS host_count\nFROM events\n  WHERE destinationport IN (80, 443)\n  AND \"Host\" IS NOT NULL\n  AND eventdirection IN ('R2L','R2R')\nGROUP BY sourceip\nHAVING host_count > 20"
    }
  ]
}

],
// ======================
// TA0006 – Credential Access
// ======================

"TA0006": [
  // ---------------------------------------------------------
  // Access to /etc/passwd
  // ---------------------------------------------------------
  {
    id: "T1003",
    name: "Credential Access – /etc/passwd Enumeration",
    description: "Detects access attempts to /etc/passwd, commonly used to enumerate users or prepare credential attacks.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `DeviceProcessEvents
| where ProcessCommandLine has_any ("cat /etc/passwd", "ls -la /etc/passwd")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName, ReportId
| extend SuspiciousActivity = "Access to /etc/passwd"`
      }
    ]
  },

  // ---------------------------------------------------------
  // Credential Dumping (Mimikatz / ProcDump)
  // ---------------------------------------------------------
  {
    id: "T1003.001",
    name: "Credential Dumping Tools Execution",
    description: "Detects well-known credential dumping tools such as Mimikatz or ProcDump.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `DeviceProcessEvents
| where FileName in ("mimikatz.exe","procdump.exe")`
      },
      {
        type: "QRadar AQL",
        lang: "qradar",
        code: `SELECT *
FROM events
WHERE domainid = 1
  AND "Process Name" IN ('mimikatz.exe');`
      }
    ]
  }
],
  // ======================
  // TA0042 – Resource Development
  // ======================
  "TA0042": [
          
  ],

  // ======================
  // TA0001 – Initial Access
  // ======================
  "TA0001": [
    {
    id: "T1204",
    name: "Suspicious Attachment",
    description: "Detects potentially malicious attachment types delivered via email such as .exe, .js, .hta.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `EmailAttachmentInfo
| where FileExtension in ("exe","js","hta")
| project RecipientEmailAddress,SenderDisplayName,SenderFromAddress,FileName,FileExtension,SHA256`
      },
      {
        type: "Splunk SPL",
        lang: "splunk",
        code: `index=proofpoint
| eval file_clean = lower(trim(file_name))
| where match(file_clean, "\\.(js|exe|hta)$")
| table action src src_user recipient file_hash file_name url subject`
      }
    ]
  },
  {
    id: "T1106",
    name: "Browser Spawning Unusual Processes",
    description: "Detects suspicious child processes spawned by browsers (potential exploitation or malicious extensions).",
    rules: [
      {
        type: "QRadar AQL",
        lang: "qradar",
        code: `SELECT *
FROM events
WHERE domainid = 1
  AND "Parent Process Name" IN (
        'chrome.exe',
        'msedge.exe',
        'firefox.exe',
        'brave.exe',
        'opera.exe',
        'iexplore.exe'
      )
  AND "Process Name" IN (
        'cmd.exe',
        'powershell.exe',
        'pwsh.exe',
        'wscript.exe',
        'cscript.exe',
        'mshta.exe',
        'rundll32.exe',
        'regsvr32.exe',
        'certutil.exe',
        'bitsadmin.exe',
        'powershell_ise.exe'
      );`
      },
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `DeviceProcessEvents
| where InitiatingProcessParentFileName in (
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "brave.exe",
        "opera.exe",
        "iexplore.exe"
    )
| where InitiatingProcessFileName in (
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe"
    )`
      }
    ]
  },
   {
      id: "T1110",
      name: "RDP Bruteforce",
      description: "Detects repeated failed RDP logons from the same IP.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `SecurityEvent
| where EventID == 4625
| where LogonType == 10
| where IpAddress != "" and IpAddress != "127.0.0.1"
| summarize FailedLogons = count(),
            Accounts = make_set(Account, 10)
            by IpAddress, bin(TimeGenerated, 5m)
| where FailedLogons >= 10`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, COUNT(*) AS failed_count, MIN(starttime) AS first_seen, MAX(starttime) AS last_seen
WHERE EventIDCode = '4625'
  AND "Logon Type" = '10'
  AND sourceip IS NOT NULL
GROUP BY sourceip
HAVING COUNT(*) >= 10`
        }
      ]
    }
  ],
  // ======================
  // TA0002 – Execution
  // ======================
  "TA0002": [
    ],
  // ======================
  // TA0003 – Persistence
  // ======================
  "TA0003": [
     {
      id: "T1547",
      name: "Registry Run Keys & Startup Folder",
      description: "Detects persistence mechanisms via Run keys or Startup folder.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let reg = DeviceRegistryEvents
| where RegistryKey contains "Run"
| extend EventType = "Registry",
         Path = RegistryKey,
         Name = RegistryValueName
| project Timestamp, DeviceId, EventType, ActionType, Path, Name,
          InitiatingProcessParentFileName;
let file = DeviceFileEvents
| where FolderPath contains "Startup"
| where ActionType == "FileCreated"
| extend EventType = "StartupFolder",
         Path = FolderPath,
         Name = FileName
| project Timestamp, DeviceId, EventType, ActionType, Path, Name,
          InitiatingProcessParentFileName;
reg
| union file
| where InitiatingProcessParentFileName !in ("gc_worker.exe","SenseCM.exe","CcmExec.exe","gc_service.exe","SenseIR.exe","svagentsRCM.exe","QualysAgent.exe")`
        }
      ]
    },

    {
      id: "T1053.005",
      name: "Scheduled Task Create or Modify",
      description: "Detects creation or modification of scheduled tasks.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `SecurityEvent
| where EventID in (4698, 4699)
| extend RawXML = tostring(EventData)
| extend Parsed = parse_xml(RawXML)
| mv-apply DataArray = Parsed.EventData.Data on 
(
    summarize bag = make_bag(pack(tostring(DataArray['@Name']), tostring(DataArray['#text'])))
)
| evaluate bag_unpack(bag, columnsConflict="update_source_value")
| project TimeGenerated,Computer,Activity,SubjectDomainName,SubjectLogonId,SubjectUserName,TaskContent,TaskName`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `Select * from events where domainid = '1' and EventIDCode = '4698'`
        }
      ]
    }
  ],

  // ======================
  // TA0004 – Privilege Escalation
  // ======================
  "TA0004": [
    {
      id: "T1068",
      name: "SUID/SGID Enumeration",
      description: "Enumeration of files with SUID/SGID bits set.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where ProcessCommandLine has_any (
    "find / -perm -u=s",
    "-perm -u=s",
    "-perm /4000",
    "find /usr/bin -perm",
    "find / -perm 4000"
)
| where ProcessCommandLine !contains "backup"
| project TimeGenerated,
          DeviceName,
          InitiatingProcessFileName,
          ProcessCommandLine,
          AccountName,
          InitiatingProcessParentFileName
| extend SuspiciousActivity = "Enumeration of SUID/SGID Files"`
        }
      ]
    },

    {
      id: "T1548",
      name: "SUID/SGID Permission Modification",
      description: "Detect attempts to set SUID or SGID permissions.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where ProcessCommandLine has_any (
    "chmod 4750",
    "chmod u+s",
    "chmod 4"
)
| where ProcessCommandLine !contains "backup"
| project TimeGenerated,
          DeviceName,
          InitiatingProcessFileName,
          ProcessCommandLine,
          AccountName,
          InitiatingProcessParentFileName
| extend SuspiciousActivity = "SUID/SGID Permission Modification"`
        }
      ]
    },

    {
      id: "T1548.001",
      name: "Abuse of Setuid/Setgid",
      description: "Detects abuse of setuid/setgid via chmod.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where ProcessCommandLine has "chmod"
| where ProcessCommandLine matches regex @"(u\\+s|g\\+s)"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName`
        }
      ]
    }
  ],   

  // ======================
  // TA0005 – Defense Evasion
  // ======================
  "TA0005": [
  // Defense Evasion rules
{
  id: "T1562.001",
  name: "Disabilitazione Antivirus / Microsoft Defender",
  description: "Tentativi di disabilitare o alterare lo stato di Defender/AV.",
  details: {
    category: "Defense Evasion",
    detailsMarkdown: ""
  },
  rules: [
    {
      type: "Splunk SPL",
      lang: "splunk",
      code: `index=wineventlog EventCode=5001 OR EventCode=5010`
    },
    {
      type: "QRadar AQL",
      lang: "qradar",
      code: `SELECT * FROM events WHERE EventID IN (5001, 5010)`
    },
    {
      type: "Sentinel KQL",
      lang: "sentinel",
      code: `SecurityEvent | where EventID in (5001, 5010)`
    }
  ]
},
{
  id: "T1562.004",
  name: "Stop / Disable di servizi di sicurezza (EDR / AV)",
  description: "Arresto o modifica dello stato dei servizi di sicurezza.",
  details: {
    category: "Defense Evasion",
    detailsMarkdown: ""
  },
  rules: [
    {
      type: "Splunk SPL",
      lang: "splunk",
      code: `index=wineventlog EventCode=7040`
    },
    {
      type: "QRadar AQL",
      lang: "qradar",
      code: `SELECT * FROM events WHERE EventID = 7040`
    },
    {
      type: "Sentinel KQL",
      lang: "sentinel",
      code: `SecurityEvent | where EventID == 7040`
    }
  ]
},
{
  id: "T1070.001",
  name: "Cancellazione Event Log",
  description: "Pulizia dei log per nascondere attività malevole.",
  details: {
    category: "Defense Evasion",
    detailsMarkdown: ""
  },
  rules: [
    {
      type: "Splunk SPL",
      lang: "splunk",
      code: `index=wineventlog EventCode=1102`
    },
    {
      type: "QRadar AQL",
      lang: "qradar",
      code: `SELECT * FROM events WHERE EventID = 1102`
    },
    {
      type: "Sentinel KQL",
      lang: "sentinel",
      code: `SecurityEvent | where EventID == 1102`
    }
  ]
}
   ],
   
 
  // ======================
  // TA0008 – Lateral Movement
  // ======================
  "TA0008": [
    {
      id: "T1021.001",
      name: "Suspicious RDP Success",
      description: "Detects successful RDP logon following multiple failures.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let Failed =
SecurityEvent
| where EventID == 4625
| where LogonType == 10
| summarize FailedCount = count() by IpAddress, Account;
let Success =
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| project IpAddress, Account, TimeGenerated;
Failed
| join kind=inner (Success) on IpAddress, Account
| where FailedCount >= 5
| project TimeGenerated, IpAddress, Account, FailedCount`
        }
      ]
    }
   ],
   // ======================
// TA0007 – Discovery
// ======================
"TA0007": [
  {
    id: "T1087.002",
    name: "AD User Enumeration — net user /domain",
    description: "Detects net.exe usage enumerating domain users.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `let timeframe = 7d;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where FileName =~ "net.exe"
| where ProcessCommandLine has "user" and ProcessCommandLine has "/domain"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, AccountName, ProcessCommandLine, ReportId
| sort by Timestamp desc`
      }
    ]
  },

  {
    id: "T1069.002",
    name: "AD Group Enumeration — net group /domain",
    description: "Detects net.exe enumerating domain groups.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `let timeframe = 7d;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where FileName =~ "net.exe"
| where ProcessCommandLine has "group" and ProcessCommandLine has "/domain"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, AccountName, ProcessCommandLine, ReportId
| sort by Timestamp desc`
      }
    ]
  },

  {
    id: "T1087",
    name: "AD Domain Enumeration via .NET",
    description: "Detects PowerShell calls to the .NET API to retrieve the current domain.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `let timeframe = 7d;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where tolower(FileName) in ("powershell.exe","pwsh.exe")
| where ProcessCommandLine contains "[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain"
| project Timestamp, DeviceName, FileName, AccountName, ProcessCommandLine, InitiatingProcessFileName, ReportId
| sort by Timestamp desc`
      }
    ]
  },

  {
    id: "T1257",
    name: "LDAP Enumeration — DirectorySearcher",
    description: "Detects instantiation of System.DirectoryServices.DirectorySearcher from PowerShell.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `let timeframe = 7d;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where tolower(FileName) in ("powershell.exe","pwsh.exe")
| where ProcessCommandLine contains "System.DirectoryServices.DirectorySearcher"
| project Timestamp, DeviceName, FileName, AccountName, ProcessCommandLine, InitiatingProcessFileName, ReportId
| sort by Timestamp desc`
      }
    ]
  },

  {
    id: "T1087",
    name: "PowerView — Get-NetDomain",
    description: "Detects PowerView Get-NetDomain usage.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `let timeframe = 7d;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where tolower(FileName) in ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has "Get-NetDomain"
| project Timestamp, DeviceName, FileName, AccountName, ProcessCommandLine, InitiatingProcessFileName, ReportId
| sort by Timestamp desc`
      }
    ]
  },

  {
    id: "T1087.002",
    name: "PowerView — Get-NetUser",
    description: "Detects Get-NetUser usage for user enumeration.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `let timeframe = 7d;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where tolower(FileName) in ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has "Get-NetUser"
| project Timestamp, DeviceName, FileName, AccountName, ProcessCommandLine, InitiatingProcessFileName, ReportId
| sort by Timestamp desc`
      }
    ]
  },

  {
    id: "T1069.002",
    name: "PowerView — Get-NetGroup",
    description: "Detects Get-NetGroup usage for group enumeration.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `let timeframe = 7d;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where tolower(FileName) in ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has "Get-NetGroup"
| project Timestamp, DeviceName, FileName, AccountName, ProcessCommandLine, InitiatingProcessFileName, ReportId
| sort by Timestamp desc`
      }
    ]
  },

  {
    id: "T1087.003",
    name: "PowerView — Get-NetComputer",
    description: "Detects Get-NetComputer usage to enumerate domain computers.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `let timeframe = 7d;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where tolower(FileName) in ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has "Get-NetComputer"
| project Timestamp, DeviceName, FileName, AccountName, ProcessCommandLine, InitiatingProcessFileName, ReportId
| sort by Timestamp desc`
      }
    ]
  },

  {
    id: "T1558.003",
    name: "Kerberoasting SPN Enumeration — setspn -L / Get-NetUser -SPN",
    description: "Detects use of setspn to enumerate SPNs and PowerView SPN lookups.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `let timeframe = 7d;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where tolower(FileName) =~ "setspn.exe"
| where ProcessCommandLine has "-l" or ProcessCommandLine has "-L"
| project Timestamp, DeviceName, FileName, AccountName, ProcessCommandLine, InitiatingProcessFileName, ReportId
| sort by Timestamp desc`
      },
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `let timeframe = 7d;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where tolower(FileName) in ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has "Get-NetUser" and ProcessCommandLine has "SPN"
| project Timestamp, DeviceName, FileName, AccountName, ProcessCommandLine, InitiatingProcessFileName, ReportId
| sort by Timestamp desc`
      }
    ]
  },

  {
    id: "T1069",
    name: "Object Permission Enumeration — Get-ObjectAcl",
    description: "Detects collection of ACLs/permissions for escalation reconnaissance.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `let timeframe = 7d;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where tolower(FileName) in ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has "Get-ObjectAcl"
| project Timestamp, DeviceName, FileName, AccountName, ProcessCommandLine, InitiatingProcessFileName, ReportId
| sort by Timestamp desc`
      }
    ]
  },

  {
    id: "T1135",
    name: "Domain Share Enumeration — Find-DomainShare",
    description: "Detects Find-DomainShare usage for discovering domain shares.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `let timeframe = 7d;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where tolower(FileName) in ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has "Find-DomainShare"
| project Timestamp, DeviceName, FileName, AccountName, ProcessCommandLine, InitiatingProcessFileName, ReportId
| sort by Timestamp desc`
      }
    ]
  },

  {
    id: "T1018",
    name: "BloodHound / SharpHound Recon",
    description: "Detects BloodHound and SharpHound collection activity.",
    details: {
      category: "Remote Services",
      detailsMarkdown: `
### 🔥 Severity
**High**
### 🔗 Riferimenti
- [MITRE T1135](https://attack.mitre.org/techniques/T1135/)
- [Event ID 4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [VirusTotal](https://www.virustotal.com/)
### 🔍 Checks da fare
1. Verificare Event ID **4625**
2. Controllare IP sorgente
3. Correlare con **4624**
4. OSINT (AbuseIPDB, VirusTotal)

### 🛠 Detection Notes
- Possibili falsi positivi
- Jump server
- Orari non lavorativi
`
    },    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `let timeframe = 14d;
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| where ProcessCommandLine matches regex @"(?i)(invoke-bloodhound|bloodhound|sharphound|sharp[hH]ound)"
| project Timestamp, DeviceName, FileName, AccountName, ProcessCommandLine, InitiatingProcessFileName, ReportId
| sort by Timestamp desc`
      }
    ]
  }
 ],
 
 
 //IMPACT
 "TA0040": [
{
  id: "T1486",
  name: "Data Encryption for Impact (Ransomware)",
  description: "Detects behaviors associated with ransomware encryption activity.",
  details: {
    category: "Impact",
    detailsMarkdown: ""
  },
  rules: [
    {
      type: "Sentinel KQL",
      lang: "sentinel",
      code: `DeviceFileEvents
| summarize FileMod=count() by DeviceName, InitiatingProcessFileName
| where FileMod > 1000`
    },
    {
      type: "Splunk SPL",
      lang: "splunk",
      code: `index=*
| stats count as FileMod by host process
| where FileMod > 1000`
    },
    {
      type: "QRadar AQL",
      lang: "qradar",
      code: `SELECT Hostname, COUNT(*) as FileMod
FROM file_events
GROUP BY Hostname
HAVING COUNT(*) > 1000`
    }
  ]
}
],

 //Data exfiltration
  "TA0010": [
{
  id: "T1041",
  name: "Large Outbound Data Transfer",
  description: "Detects unusually large outbound data transfers that may indicate data exfiltration.",
  details: {
    category: "Exfiltration",
    detailsMarkdown: ""
  },
  rules: [
    {
      type: "Sentinel KQL",
      lang: "sentinel",
      code: `CommonSecurityLog
| summarize BytesSent=sum(SentBytes) by SourceIP, DestinationIP
| where BytesSent > 50000000`
    },
    {
      type: "Splunk SPL",
      lang: "splunk",
      code: `index=network
| stats sum(bytes_out) as BytesSent by src_ip dest_ip
| where BytesSent > 50000000`
    },
    {
      type: "QRadar AQL",
      lang: "qradar",
      code: `SELECT SourceIP, DestinationIP, SUM(BytesSent)
FROM events
GROUP BY SourceIP, DestinationIP
HAVING SUM(BytesSent) > 50000000`
    }
  ]
}
]
 
 
};

 
 
// DOM Elements
const matrixGrid = document.getElementById('matrix-grid');
const searchInput = document.getElementById('search-input');
const sidebar = document.getElementById('sidebar');
const sidebarOverlay = document.getElementById('sidebar-overlay');

// Icons
const ICONS = {
  splunk: '<div class="h-2 w-2 rounded-full bg-green-500"></div>',
  elastic: '<div class="h-2 w-2 rounded-full bg-blue-500"></div>',
  sigma: '<div class="h-2 w-2 rounded-full bg-yellow-500"></div>',
  sentinel: '<div class="h-2 w-2 rounded-full bg-purple-500"></div>'
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  if (matrixGrid) {
    renderMatrix();
    setupSearch();
  }
  setupSidebarTabs();
});

// --- MATRIX ---
function renderMatrix() {
  if (!matrixGrid) return;
  matrixGrid.innerHTML = '';

  TACTICS.forEach(tactic => {
    const column = document.createElement('div');
    column.className = 'tactic-column';

    const header = document.createElement('div');
    header.className = 'tactic-header';
    header.innerHTML = `<div class="tactic-title">${tactic.name}</div>
                        <div class="tactic-count">${tactic.id}</div>`;

    const list = document.createElement('div');
    list.className = 'technique-list';
    const tacticsTechniques = TECHNIQUES[tactic.id] || [];

    tacticsTechniques.forEach(tech => {
      const card = document.createElement('div');
      card.className = 'technique-card';
      card.onclick = () => openSidebar(tech);
      card.innerHTML = `<div class="tech-name">${tech.name}</div>
                        ${tech.subtechniques?.length ? '<div class="sub-indicator"></div>' : ''}`;
      list.appendChild(card);
    });

    column.appendChild(header);
    column.appendChild(list);
    matrixGrid.appendChild(column);
  });
}

function renderMarkdown(md) {
  return md
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>')
    .replace(/^### (.*$)/gim, '<h3>$1</h3>')
    .replace(/^## (.*$)/gim, '<h2>$1</h2>')
    .replace(/^# (.*$)/gim, '<h1>$1</h1>')
    .replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>')
    .replace(/\n\d+\. (.*)/g, '<li>$1</li>')
    .replace(/\n/g, '<br>');
}

function setupSearch() {
  if (!searchInput) return;
  searchInput.addEventListener('input', e => {
    const query = e.target.value.toLowerCase();
    document.querySelectorAll('.technique-card').forEach(card => {
      card.style.opacity = card.innerText.toLowerCase().includes(query) ? '1' : '0.2';
    });
  });
}

// --- SIDEBAR ---
function openSidebar(tech) {
  if (!sidebar || !sidebarOverlay) return;
  
  sidebar.querySelector('#sb-title').textContent = tech.name || '';
  sidebar.querySelector('#sb-id').textContent = tech.id || '';
  sidebar.querySelector('#sb-desc').textContent = tech.description || '';
  
  
	const sub = sidebar.querySelector('#sb-subtechniques');
const details = sidebar.querySelector('#sb-details');

/* Subtechniques */
sub.innerHTML = tech.subtechniques?.length
  ? tech.subtechniques.map(s => `<span class="badge">${s}</span>`).join('')
  : '<span class="text-muted"></span>';

/* Details markdown */
if (tech.details?.detailsMarkdown) {
  details.innerHTML = renderMarkdown(tech.details.detailsMarkdown);
} else {
  details.innerHTML = '<span class="text-muted">No additional notes</span>';
}

    renderRules(tech.rules || []);

  // Show sidebar & overlay
  sidebar.classList.add('open');
  sidebarOverlay.classList.add('open');

  // Prevent overlay from blocking tab clicks
  sidebarOverlay.addEventListener('click', closeSidebar);
}

function closeSidebar() {
  if (!sidebar || !sidebarOverlay) return;
  sidebar.classList.remove('open');
  sidebarOverlay.classList.remove('open');
}

function renderRules(rules) {
  const container = document.getElementById('sb-rules-list');
  if (!container) return;
  container.innerHTML = rules.length
    ? rules.map(rule => `
      <div class="rule-block mb-4">
        <h4 class="font-semibold flex items-center gap-2 text-sm mb-2">
          ${ICONS[rule.lang] || ''} ${rule.type}
        </h4>
        <div class="code-block">
          <span class="code-lang">${rule.lang}</span>
          <pre>${rule.code}</pre>
        </div>
      </div>
    `).join('')
    : '<p class="text-muted">No rules defined for this technique.</p>';
}

// --- TABS ---
function setupSidebarTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      const tabName = e.target.dataset.tab;
      switchTab(tabName);
    });
  });
}

function switchTab(tabName) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

  const btn = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);
  const content = document.getElementById(`tab-${tabName}`);
  if (btn) btn.classList.add('active');
  if (content) content.classList.add('active');
}

// Expose globally
window.closeSidebar = closeSidebar;
window.switchTab = switchTab;
