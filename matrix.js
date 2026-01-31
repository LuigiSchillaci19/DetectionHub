
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
    name: "LSASS Memory Dumping",
    description: "Detects attempts to dump LSASS memory for credential extraction using tools like Mimikatz, ProcDump, or comsvcs.dll.",
    details: {
      category: "Credential Access",
      detailsMarkdown: `
### 🔥 Severity
**Critical**

### 🔗 References
- [MITRE T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [Detecting Credential Dumping](https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107)

### 🔍 Detection Notes
- Monitor for access to lsass.exe process
- Look for comsvcs.dll MiniDump exports
- ProcDump with -ma flag targeting lsass
- Mimikatz sekurlsa commands
`
    },
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `let LsassDumpTools = dynamic(["mimikatz.exe", "procdump.exe", "procdump64.exe", "sqldumper.exe", "nanodump.exe"]);
let LsassDumpCommands = dynamic(["sekurlsa", "lsadump", "MiniDump", "comsvcs", "-ma lsass", "lsass.dmp"]);
union (
    DeviceProcessEvents
    | where FileName in~ (LsassDumpTools)
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
),
(
    DeviceProcessEvents
    | where ProcessCommandLine has_any (LsassDumpCommands)
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
)`
      },
      {
        type: "Splunk SPL",
        lang: "splunk",
        code: `index=windows (EventCode=1 OR EventCode=4688)
((Image="*\\mimikatz.exe" OR Image="*\\procdump.exe" OR Image="*\\procdump64.exe")
OR (CommandLine="*sekurlsa*" OR CommandLine="*lsadump*" OR CommandLine="*MiniDump*" OR CommandLine="*comsvcs*" OR CommandLine="*-ma lsass*"))
| stats count by Computer, User, Image, CommandLine`
      },
      {
        type: "QRadar AQL",
        lang: "qradar",
        code: `SELECT sourceip, username, "Process Name" as proc, "Process CommandLine" as cmdline FROM events
WHERE ("Process Name" ILIKE '%mimikatz.exe' OR "Process Name" ILIKE '%procdump%')
OR ("Process CommandLine" ILIKE '%sekurlsa%' OR "Process CommandLine" ILIKE '%lsadump%' OR "Process CommandLine" ILIKE '%MiniDump%')
LAST 24 HOURS`
      },
      {
        type: "Elastic EQL",
        lang: "elastic",
        code: `process where event.type == "start" and
(process.name : ("mimikatz.exe", "procdump.exe", "procdump64.exe") or
process.command_line : ("*sekurlsa*", "*lsadump*", "*MiniDump*", "*comsvcs*", "*-ma lsass*"))`
      },
      {
        type: "Sigma",
        lang: "sigma",
        code: `title: LSASS Memory Dumping - T1003.001
id: a1b2c3d4-5678-90ab-cdef-000003001001
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        Image|endswith:
            - '\\mimikatz.exe'
            - '\\procdump.exe'
            - '\\procdump64.exe'
    selection_commands:
        CommandLine|contains:
            - 'sekurlsa'
            - 'lsadump'
            - 'MiniDump'
            - 'comsvcs'
            - '-ma lsass'
    condition: selection_tools or selection_commands
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001`
      }
    ]
  },
  // T1003.002 - SAM Database
  {
    id: "T1003.002",
    name: "SAM Database Access",
    description: "Detects attempts to access the SAM database for credential extraction.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `DeviceProcessEvents
| where ProcessCommandLine has_any ("reg save", "reg export")
| where ProcessCommandLine has_any ("sam", "system", "security", "hklm\\sam", "hklm\\system")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`
      },
      {
        type: "Splunk SPL",
        lang: "splunk",
        code: `index=windows (EventCode=1 OR EventCode=4688)
(CommandLine="*reg save*" OR CommandLine="*reg export*")
(CommandLine="*sam*" OR CommandLine="*system*" OR CommandLine="*security*" OR CommandLine="*hklm\\sam*")
| stats count by Computer, User, CommandLine`
      },
      {
        type: "Sigma",
        lang: "sigma",
        code: `title: SAM Database Credential Dumping - T1003.002
id: b2c3d4e5-6789-01ab-cdef-000003001002
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection_reg:
        CommandLine|contains:
            - 'reg save'
            - 'reg export'
    selection_hive:
        CommandLine|contains:
            - 'sam'
            - 'system'
            - 'security'
    condition: selection_reg and selection_hive
level: critical
tags:
    - attack.credential_access
    - attack.t1003.002`
      }
    ]
  },
  // T1003.003 - NTDS
  {
    id: "T1003.003",
    name: "NTDS.dit Access",
    description: "Detects attempts to access or copy the NTDS.dit Active Directory database.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `DeviceProcessEvents
| where ProcessCommandLine has_any ("ntdsutil", "vssadmin", "ntds.dit", "ifm")
| where ProcessCommandLine has_any ("create", "copy", "activate", "snapshot")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`
      },
      {
        type: "Splunk SPL",
        lang: "splunk",
        code: `index=windows (EventCode=1 OR EventCode=4688)
(CommandLine="*ntdsutil*" OR CommandLine="*vssadmin*")
(CommandLine="*ntds.dit*" OR CommandLine="*ifm*" OR CommandLine="*create*" OR CommandLine="*snapshot*")
| stats count by Computer, User, Image, CommandLine`
      },
      {
        type: "QRadar AQL",
        lang: "qradar",
        code: `SELECT sourceip, username, "Process CommandLine" as cmdline FROM events
WHERE ("Process CommandLine" ILIKE '%ntdsutil%' OR "Process CommandLine" ILIKE '%vssadmin%')
AND ("Process CommandLine" ILIKE '%ntds.dit%' OR "Process CommandLine" ILIKE '%ifm%')
LAST 24 HOURS`
      },
      {
        type: "Sigma",
        lang: "sigma",
        code: `title: NTDS.dit Credential Dumping - T1003.003
id: c3d4e5f6-7890-12bc-def0-000003001003
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection_tool:
        CommandLine|contains:
            - 'ntdsutil'
            - 'vssadmin'
    selection_target:
        CommandLine|contains:
            - 'ntds.dit'
            - 'ifm'
            - 'snapshot'
    condition: selection_tool and selection_target
level: critical
tags:
    - attack.credential_access
    - attack.t1003.003`
      }
    ]
  },
  // T1003.004 - LSA Secrets
  {
    id: "T1003.004",
    name: "LSA Secrets Dumping",
    description: "Detects attempts to dump LSA secrets from the registry.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `DeviceProcessEvents
| where ProcessCommandLine has_any ("lsa", "secrets", "policy\\secrets", "lsadump::secrets")
| where FileName in~ ("reg.exe", "mimikatz.exe", "secretsdump.py")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`
      },
      {
        type: "Sigma",
        lang: "sigma",
        code: `title: LSA Secrets Dumping - T1003.004
id: d4e5f6a7-8901-23cd-ef01-000003001004
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'lsadump::secrets'
            - 'Policy\\Secrets'
            - 'LSA Secrets'
    condition: selection
level: critical
tags:
    - attack.credential_access
    - attack.t1003.004`
      }
    ]
  },
  // T1003.005 - Cached Domain Credentials
  {
    id: "T1003.005",
    name: "Cached Domain Credentials",
    description: "Detects attempts to extract cached domain credentials.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `DeviceProcessEvents
| where ProcessCommandLine has_any ("cachedump", "lsadump::cache", "mscash", "DCC2")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`
      },
      {
        type: "Sigma",
        lang: "sigma",
        code: `title: Cached Domain Credentials Extraction - T1003.005
id: e5f6a7b8-9012-34de-f012-000003001005
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'cachedump'
            - 'lsadump::cache'
            - 'mscash'
            - 'DCC2'
    condition: selection
level: high
tags:
    - attack.credential_access
    - attack.t1003.005`
      }
    ]
  },
  // T1003.006 - DCSync
  {
    id: "T1003.006",
    name: "DCSync Attack",
    description: "Detects DCSync attacks used to replicate domain credentials.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `SecurityEvent
| where EventID == 4662
| where ObjectType contains "domainDNS"
| where Properties has_any ("Replicating Directory Changes All", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
| project TimeGenerated, Computer, SubjectUserName, ObjectName, Properties`
      },
      {
        type: "Splunk SPL",
        lang: "splunk",
        code: `index=windows EventCode=4662
(Properties="*Replicating Directory Changes All*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")
| stats count by src_user, ObjectName`
      },
      {
        type: "QRadar AQL",
        lang: "qradar",
        code: `SELECT sourceip, username, "Object Name" as object FROM events
WHERE "EventID" = '4662'
AND ("Access Mask" ILIKE '%Replicating Directory Changes%' OR "Properties" ILIKE '%1131f6ad%')
LAST 24 HOURS`
      },
      {
        type: "Sigma",
        lang: "sigma",
        code: `title: DCSync Attack Detection - T1003.006
id: f6a7b8c9-0123-45ef-0123-000003001006
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains:
            - 'Replicating Directory Changes All'
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    condition: selection
level: critical
tags:
    - attack.credential_access
    - attack.t1003.006`
      }
    ]
  },
  // T1555.003 - Credentials from Web Browsers
  {
    id: "T1555.003",
    name: "Browser Credential Theft",
    description: "Detects access to browser credential stores and password databases.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `DeviceFileEvents
| where FileName in~ ("Login Data", "logins.json", "cookies.sqlite", "key3.db", "key4.db", "signons.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe", "firefox.exe", "msedge.exe", "brave.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName`
      },
      {
        type: "Splunk SPL",
        lang: "splunk",
        code: `index=sysmon (EventCode=11 OR EventCode=23)
(TargetFilename="*Login Data*" OR TargetFilename="*logins.json*" OR TargetFilename="*cookies.sqlite*" OR TargetFilename="*key4.db*")
NOT (Image="*\\chrome.exe" OR Image="*\\firefox.exe" OR Image="*\\msedge.exe")
| stats count by Computer, Image, TargetFilename`
      },
      {
        type: "Sigma",
        lang: "sigma",
        code: `title: Browser Credential Theft - T1555.003
id: a7b8c9d0-1234-56f0-1234-000555003000
status: stable
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
            - 'Login Data'
            - 'logins.json'
            - 'cookies.sqlite'
            - 'key4.db'
    filter:
        Image|endswith:
            - '\\chrome.exe'
            - '\\firefox.exe'
            - '\\msedge.exe'
    condition: selection and not filter
level: high
tags:
    - attack.credential_access
    - attack.t1555.003`
      }
    ]
  },
  // T1558.003 - Kerberoasting
  {
    id: "T1558.003",
    name: "Kerberoasting",
    description: "Detects Kerberoasting attacks targeting service account tickets.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `SecurityEvent
| where EventID == 4769
| where ServiceName !endswith "$"
| where TicketEncryptionType in ("0x17", "0x18")
| summarize TicketCount = count(), ServiceAccounts = make_set(ServiceName) by IpAddress, TargetUserName, bin(TimeGenerated, 1h)
| where TicketCount > 10`
      },
      {
        type: "Splunk SPL",
        lang: "splunk",
        code: `index=windows EventCode=4769 Ticket_Encryption_Type IN ("0x17", "0x18")
| where Service_Name!="*$"
| stats count dc(Service_Name) as unique_services by Client_Address, user, _time span=1h
| where count > 10 OR unique_services > 5`
      },
      {
        type: "QRadar AQL",
        lang: "qradar",
        code: `SELECT sourceip, username, "Service Name" as service, COUNT(*) as ticket_count FROM events
WHERE "EventID" = '4769'
AND ("Ticket Encryption Type" = '0x17' OR "Ticket Encryption Type" = '0x18')
AND "Service Name" NOT ILIKE '%$'
GROUP BY sourceip, username, "Service Name"
HAVING ticket_count > 10
LAST 24 HOURS`
      },
      {
        type: "Sigma",
        lang: "sigma",
        code: `title: Kerberoasting Detection - T1558.003
id: b8c9d0e1-2345-67a1-2345-000558003000
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType:
            - '0x17'
            - '0x18'
    filter:
        ServiceName|endswith: '$'
    condition: selection and not filter
level: high
tags:
    - attack.credential_access
    - attack.t1558.003`
      }
    ]
  },
  // T1552.001 - Credentials in Files
  {
    id: "T1552.001",
    name: "Credentials in Files",
    description: "Detects searches for credentials stored in files.",
    rules: [
      {
        type: "Sentinel KQL",
        lang: "sentinel",
        code: `DeviceProcessEvents
| where ProcessCommandLine has_any ("findstr", "Select-String", "grep")
| where ProcessCommandLine has_any ("password", "passwd", "pwd", "credential", "secret", "apikey", "api_key", "token")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`
      },
      {
        type: "Splunk SPL",
        lang: "splunk",
        code: `index=windows (EventCode=1 OR EventCode=4688)
(CommandLine="*findstr*" OR CommandLine="*Select-String*")
(CommandLine="*password*" OR CommandLine="*passwd*" OR CommandLine="*credential*" OR CommandLine="*secret*" OR CommandLine="*apikey*")
| stats count by Computer, User, CommandLine`
      },
      {
        type: "Sigma",
        lang: "sigma",
        code: `title: Credential Search in Files - T1552.001
id: c9d0e1f2-3456-78b2-3456-000552001000
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection_search:
        CommandLine|contains:
            - 'findstr'
            - 'Select-String'
            - 'grep'
    selection_keywords:
        CommandLine|contains:
            - 'password'
            - 'passwd'
            - 'credential'
            - 'secret'
            - 'apikey'
    condition: selection_search and selection_keywords
level: medium
tags:
    - attack.credential_access
    - attack.t1552.001`
      }
    ]
  }
],
  // ======================
  // TA0042 – Resource Development
  // ======================
  "TA0042": [
    // T1583.001 - Acquire Infrastructure: Domains
    {
      id: "T1583.001",
      name: "Domain Registration Monitoring",
      description: "Monitor for newly registered domains that may be used for malicious purposes (typosquatting, lookalike domains).",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `// Monitor DNS queries to newly registered domains
// Requires TI feed with NRD (Newly Registered Domains)
let NRD_Threshold = 30d;
DnsEvents
| join kind=inner (
    ThreatIntelligenceIndicator
    | where isnotempty(DomainName)
    | where ExpirationDateTime > now()
    | project DomainName, ThreatType, ConfidenceScore
) on $left.Name == $right.DomainName
| project TimeGenerated, Computer, Name, ThreatType, ConfidenceScore`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `| tstats count from datamodel=Network_Resolution where * by DNS.query
| lookup newly_registered_domains.csv domain as DNS.query OUTPUT creation_date
| where creation_date > relative_time(now(), "-30d")
| table DNS.query, creation_date, count`
        }
      ]
    },
    // T1584.001 - Compromise Infrastructure: Domains
    {
      id: "T1584.001",
      name: "Compromised Domain Detection",
      description: "Detect connections to domains that have been flagged as compromised.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let CompromisedDomains = ThreatIntelligenceIndicator
| where ThreatType == "CompromisedInfrastructure"
| project DomainName;
DnsEvents
| where Name in (CompromisedDomains)
| project TimeGenerated, Computer, ClientIP, Name`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `| tstats count from datamodel=Network_Resolution by DNS.query, DNS.src
| lookup compromised_domains.csv domain as DNS.query OUTPUT threat_type
| where isnotnull(threat_type)
| table DNS.src, DNS.query, threat_type, count`
        }
      ]
    },
    // T1588.002 - Obtain Capabilities: Tool
    {
      id: "T1588.002",
      name: "Malicious Tool Download",
      description: "Detect downloads of known offensive security tools and malware.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceNetworkEvents
| where RemoteUrl has_any ("github.com/gentilkiwi/mimikatz", "github.com/PowerShellMafia", "github.com/BloodHoundAD", "cobalt", "metasploit", "empire")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=proxy OR index=network
(url="*mimikatz*" OR url="*PowerShellMafia*" OR url="*BloodHoundAD*" OR url="*cobalt*" OR url="*metasploit*")
| stats count by src_ip, url, user`
        }
      ]
    },
    // T1587.001 - Develop Capabilities: Malware
    {
      id: "T1587.001",
      name: "Malware Development Artifacts",
      description: "Detect indicators of malware development activity.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where FileName in~ ("msfvenom.exe", "veil.exe", "shellter.exe", "unicorn.py")
    or ProcessCommandLine has_any ("msfvenom", "pyinstaller", "--payload", "shellcode", "encoder")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Malware Development Tools - T1587.001
id: a1b2c3d4-5678-90ab-cdef-000587001000
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'msfvenom'
            - 'pyinstaller'
            - 'shellcode'
            - 'encoder'
    condition: selection
level: high
tags:
    - attack.resource_development
    - attack.t1587.001`
        }
      ]
    }
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
      id: "T1566.002",
      name: "Spearphishing Link",
      description: "Detects clicks on suspicious URLs in emails including URL shorteners and suspicious TLDs.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let urlShorteners = dynamic(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]);
let suspiciousTLDs = dynamic([".xyz", ".top", ".click", ".link", ".work", ".tk"]);
EmailUrlInfo
| where Url has_any (urlShorteners) or Url has_any (suspiciousTLDs)
| join kind=inner (EmailEvents | where EmailDirection == "Inbound") on NetworkMessageId
| project TimeGenerated, RecipientEmailAddress, SenderFromAddress, Url, Subject`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=email OR index=proxy
| where match(url, "(bit\\.ly|tinyurl\\.com|t\\.co|goo\\.gl|ow\\.ly)")
OR match(url, "\\.(xyz|top|click|link|work|tk)/")
| stats count values(url) as urls by sender, src_user, subject`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, username, url, "Email Subject" as subject FROM events
WHERE LOGSOURCETYPENAME(logsourceid) ILIKE '%mail%' OR LOGSOURCETYPENAME(logsourceid) ILIKE '%proxy%'
AND (url ILIKE '%bit.ly%' OR url ILIKE '%tinyurl.com%' OR url ILIKE '%.xyz/%' OR url ILIKE '%.top/%')
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `any where event.category == "email" and
(url.domain : ("bit.ly", "tinyurl.com", "t.co", "goo.gl")
or url.top_level_domain : ("xyz", "top", "click", "link", "work", "tk"))`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Spearphishing Link Detection - T1566.002
id: 8f4b2e1a-5c3d-4e6f-9a7b-1c2d3e4f5678
status: experimental
logsource:
    category: proxy
detection:
    selection_shorteners:
        c-uri|contains:
            - 'bit.ly'
            - 'tinyurl.com'
            - 't.co'
    selection_tlds:
        c-uri|contains:
            - '.xyz/'
            - '.top/'
            - '.click/'
    condition: selection_shorteners or selection_tlds
level: medium
tags:
    - attack.initial_access
    - attack.t1566.002`
        }
      ]
    },
    {
      id: "T1566.003",
      name: "Spearphishing via Service",
      description: "Detects malicious links and file sharing through external collaboration services like Teams, Slack, Discord.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let suspiciousDomains = dynamic([".xyz", ".top", ".click", "bit.ly", "tinyurl.com"]);
let suspiciousFileTypes = dynamic([".exe", ".scr", ".bat", ".ps1", ".vbs", ".js", ".hta", ".iso"]);
OfficeActivity
| where RecordType in ("MicrosoftTeams", "ThreatIntelligence")
| where Operation in ("MessageCreatedHasLink", "ChatCreated", "FileUploaded")
| extend MessageURLs = extract_all(@"https?://[^\\s]+", tostring(MessageURLs))
| mv-expand MessageURLs
| where tostring(MessageURLs) has_any (suspiciousDomains)
| project TimeGenerated, UserId, Operation, MessageURLs, CommunicationType`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=o365 OR index=cloudapps RecordType="MicrosoftTeams" OR app IN ("Slack", "Discord", "Microsoft Teams")
| where match(MessageURLs, "(bit\\.ly|tinyurl\\.com|\\.(xyz|top|click)/)")
OR match(ObjectName, "\\.(exe|scr|bat|ps1|vbs|js|hta|iso)$")
| stats count values(MessageURLs) as links by sender, user, app`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, username, "Application" as app, url, filename FROM events
WHERE ("Application" ILIKE '%Teams%' OR "Application" ILIKE '%Slack%' OR "Application" ILIKE '%Discord%')
AND (url ILIKE '%bit.ly%' OR url ILIKE '%.xyz/%' OR filename ILIKE '%.exe' OR filename ILIKE '%.ps1' OR filename ILIKE '%.iso')
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `any where event.dataset in ("o365.audit", "slack.audit", "discord.events") and
(event.action in ("MessageCreatedHasLink", "FileShared", "MessageSent") and
(url.domain : ("bit.ly", "tinyurl.com") or url.top_level_domain : ("xyz", "top", "click") or
file.extension : ("exe", "scr", "bat", "ps1", "vbs", "js", "hta", "iso")))`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Spearphishing via Service - T1566.003
id: 9a5c3f2b-6d4e-5f7a-8b9c-2d3e4f5a6789
status: experimental
logsource:
    service: o365
    product: m365
detection:
    selection_platform:
        RecordType: 'MicrosoftTeams'
        Operation:
            - 'MessageCreatedHasLink'
            - 'FileUploaded'
    selection_urls:
        MessageURLs|contains:
            - 'bit.ly'
            - 'tinyurl.com'
            - '.xyz/'
    selection_files:
        ObjectName|endswith:
            - '.exe'
            - '.ps1'
            - '.iso'
    condition: selection_platform and (selection_urls or selection_files)
level: high
tags:
    - attack.initial_access
    - attack.t1566.003`
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
    {
      id: "T1059.003",
      name: "Windows Command Shell Abuse",
      description: "Detects suspicious cmd.exe abuse including encoded commands, certutil/bitsadmin downloads, and reconnaissance commands.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `SecurityEvent
| where EventID == 4688
| where Process has "cmd.exe"
| where CommandLine has_any ("certutil -decode", "certutil -urlcache", "bitsadmin /transfer", "whoami", "net user", "systeminfo", "ipconfig /all")
| project TimeGenerated, Computer, Account, CommandLine, ParentProcessName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=4688) process_name="*cmd.exe*"
(CommandLine="*certutil*" OR CommandLine="*bitsadmin*" OR CommandLine="*whoami*" OR CommandLine="*net user*" OR CommandLine="*systeminfo*")
| stats count by Computer, User, CommandLine, ParentImage`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, username, "Process CommandLine" as cmdline FROM events
WHERE "Process Name" ILIKE '%cmd.exe'
AND ("Process CommandLine" ILIKE '%certutil%' OR "Process CommandLine" ILIKE '%bitsadmin%' OR "Process CommandLine" ILIKE '%whoami%')
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `process where event.type == "start" and process.name : "cmd.exe" and
process.command_line : ("*certutil*decode*", "*bitsadmin*transfer*", "*whoami*", "*net user*", "*systeminfo*")`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Suspicious CMD Execution - T1059.003
id: b9f8c7d6-e5a4-3b2c-1d0e-9f8a7b6c5d4e
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd:
        Image|endswith: '\\cmd.exe'
    selection_suspicious:
        CommandLine|contains:
            - 'certutil'
            - 'bitsadmin'
            - 'whoami'
            - 'net user'
    condition: selection_cmd and selection_suspicious
level: high
tags:
    - attack.execution
    - attack.t1059.003`
        }
      ]
    },
    {
      id: "T1059.005",
      name: "VBScript Execution",
      description: "Detects suspicious VBScript execution via cscript/wscript including WScript.Shell usage and malicious patterns.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where FileName has_any ("wscript.exe", "cscript.exe")
| where ProcessCommandLine has_any ("WScript.Shell", "Shell.Application", "Scripting.FileSystemObject", "\\\\temp\\\\", "\\\\appdata\\\\")
    or InitiatingProcessFileName has_any ("WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688)
(Image="*wscript.exe" OR Image="*cscript.exe")
(CommandLine="*WScript.Shell*" OR CommandLine="*\\temp\\*" OR CommandLine="*\\appdata\\*")
| stats count by Computer, User, Image, CommandLine, ParentImage`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, username, "Process CommandLine" as cmdline FROM events
WHERE ("Process Name" ILIKE '%wscript.exe' OR "Process Name" ILIKE '%cscript.exe')
AND ("Process CommandLine" ILIKE '%WScript.Shell%' OR "Process CommandLine" ILIKE '%\\temp\\%')
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `process where event.type == "start" and process.name : ("wscript.exe", "cscript.exe") and
(process.command_line : ("*WScript.Shell*", "*Shell.Application*", "*\\\\Temp\\\\*", "*\\\\AppData\\\\*")
or process.parent.name : ("WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE"))`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Suspicious VBScript Execution - T1059.005
id: c8e7f6d5-a4b3-2c1d-0e9f-8a7b6c5d4e3f
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_engine:
        Image|endswith:
            - '\\wscript.exe'
            - '\\cscript.exe'
    selection_suspicious:
        CommandLine|contains:
            - 'WScript.Shell'
            - '\\Temp\\'
            - '\\AppData\\'
    condition: selection_engine and selection_suspicious
level: high
tags:
    - attack.execution
    - attack.t1059.005`
        }
      ]
    },
    {
      id: "T1059.006",
      name: "Python Execution",
      description: "Detects suspicious Python execution including encoded commands, network activity, and malicious pip installations.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where FileName in~ ("python.exe", "python3.exe", "pythonw.exe", "pip.exe", "pip3.exe")
| where ProcessCommandLine has_any ("-c", "exec(", "eval(", "base64", "subprocess", "socket", "urllib")
    or (FileName in~ ("pip.exe", "pip3.exe") and ProcessCommandLine has "install" and ProcessCommandLine has_any ("--index-url", "http://"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688)
(Image="*python*.exe" AND (CommandLine="*-c *" OR CommandLine="*exec(*" OR CommandLine="*base64*" OR CommandLine="*socket*"))
OR ((Image="*pip.exe" OR Image="*pip3.exe") AND CommandLine="*install*" AND CommandLine="*--index-url*")
| stats count by Computer, User, Image, CommandLine, ParentImage`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, username, "Process CommandLine" as cmdline FROM events
WHERE ("Process Name" ILIKE '%python%' AND ("Process CommandLine" ILIKE '% -c %' OR "Process CommandLine" ILIKE '%exec(%' OR "Process CommandLine" ILIKE '%base64%'))
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `process where event.type == "start" and process.name : ("python.exe", "python3.exe", "pythonw.exe") and
process.command_line : ("*-c *", "*exec(*", "*eval(*", "*base64*", "*subprocess*", "*socket*")`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Suspicious Python Execution - T1059.006
id: e8b9c0d1-2e3f-4a5b-6c7d-8e9f0a1b2c3d
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_python:
        Image|endswith:
            - '\\python.exe'
            - '\\python3.exe'
    selection_suspicious:
        CommandLine|contains:
            - ' -c '
            - 'exec('
            - 'base64'
            - 'socket'
    condition: selection_python and selection_suspicious
level: high
tags:
    - attack.execution
    - attack.t1059.006`
        }
      ]
    },
    {
      id: "T1059.007",
      name: "JavaScript Execution",
      description: "Detects suspicious JavaScript execution via Windows Script Host, mshta, or Node.js.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where FileName has_any ("wscript.exe", "cscript.exe", "mshta.exe", "node.exe")
| where ProcessCommandLine has_any (".js", "javascript:", "jscript:", ".jse")
    or (FileName =~ "mshta.exe" and ProcessCommandLine has_any ("javascript", "vbscript"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688)
((Image="*wscript.exe" OR Image="*cscript.exe") AND (CommandLine="*.js*" OR CommandLine="*.jse*"))
OR (Image="*mshta.exe" AND (CommandLine="*javascript:*" OR CommandLine="*jscript:*"))
OR (Image="*node.exe" AND (CommandLine="*\\temp\\*" OR CommandLine="*-e *" OR CommandLine="*--eval*"))
| stats count by Computer, User, Image, CommandLine, ParentImage`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, username, "Process CommandLine" as cmdline FROM events
WHERE (("Process Name" ILIKE '%wscript.exe' OR "Process Name" ILIKE '%cscript.exe') AND "Process CommandLine" ILIKE '%.js%')
OR ("Process Name" ILIKE '%mshta.exe' AND "Process CommandLine" ILIKE '%javascript%')
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `process where event.type == "start" and
((process.name : ("wscript.exe", "cscript.exe") and process.command_line : ("*.js*", "*.jse*"))
or (process.name : "mshta.exe" and process.command_line : ("*javascript:*", "*jscript:*")))`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Suspicious JavaScript Execution - T1059.007
id: f7a8b9c0-1d2e-3f4a-5b6c-7d8e9f0a1b2c
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_wscript:
        Image|endswith:
            - '\\wscript.exe'
            - '\\cscript.exe'
        CommandLine|contains:
            - '.js'
            - '.jse'
    selection_mshta:
        Image|endswith: '\\mshta.exe'
        CommandLine|contains:
            - 'javascript:'
            - 'jscript:'
    condition: selection_wscript or selection_mshta
level: high
tags:
    - attack.execution
    - attack.t1059.007`
        }
      ]
    },
    // T1059.001 - PowerShell
    {
      id: "T1059.001",
      name: "PowerShell Execution",
      description: "Detects suspicious PowerShell execution including encoded commands, download cradles, AMSI bypass, and obfuscation techniques.",
      details: {
        category: "Execution",
        detailsMarkdown: `
### 🔥 Severity
**Critical**

### 🔗 References
- [MITRE T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [PowerShell Logging](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging)

### 🔍 Detection Notes
- Look for encoded commands (-enc, -EncodedCommand)
- Download cradles (IEX, DownloadString, Invoke-WebRequest)
- AMSI bypass attempts
- Obfuscation techniques (string concatenation, base64)
`
      },
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let SuspiciousCommands = dynamic([
  "-EncodedCommand", "-enc ", "-ec ", "-e ",
  "IEX", "Invoke-Expression",
  "DownloadString", "DownloadFile", "DownloadData",
  "Invoke-WebRequest", "IWR", "Invoke-RestMethod",
  "Net.WebClient", "WebRequest",
  "FromBase64String", "ToBase64String",
  "-nop", "-noni", "-noninteractive",
  "-w hidden", "-windowstyle hidden",
  "bypass", "unrestricted",
  "AmsiUtils", "amsiInitFailed",
  "Invoke-Mimikatz", "Invoke-Shellcode",
  "Invoke-Obfuscation", "Out-EncodedCommand"
]);
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| where ProcessCommandLine has_any (SuspiciousCommands)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| extend ThreatIndicator = "Suspicious PowerShell Execution"`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=4688 OR EventCode=1)
(process_name="*powershell.exe" OR process_name="*pwsh.exe")
(CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *" OR CommandLine="*-e *"
OR CommandLine="*IEX*" OR CommandLine="*Invoke-Expression*"
OR CommandLine="*DownloadString*" OR CommandLine="*DownloadFile*"
OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*Net.WebClient*"
OR CommandLine="*FromBase64String*" OR CommandLine="*-w hidden*"
OR CommandLine="*bypass*" OR CommandLine="*AmsiUtils*")
| stats count values(CommandLine) as commands by Computer, User, ParentImage
| where count > 0`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, username, "Process Name" as process, "Process CommandLine" as cmdline,
       "Parent Process Name" as parent FROM events
WHERE ("Process Name" ILIKE '%powershell.exe' OR "Process Name" ILIKE '%pwsh.exe')
AND ("Process CommandLine" ILIKE '%-EncodedCommand%'
  OR "Process CommandLine" ILIKE '%-enc %'
  OR "Process CommandLine" ILIKE '%IEX%'
  OR "Process CommandLine" ILIKE '%Invoke-Expression%'
  OR "Process CommandLine" ILIKE '%DownloadString%'
  OR "Process CommandLine" ILIKE '%Invoke-WebRequest%'
  OR "Process CommandLine" ILIKE '%FromBase64String%'
  OR "Process CommandLine" ILIKE '%-w hidden%'
  OR "Process CommandLine" ILIKE '%bypass%')
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `process where event.type == "start" and
process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and
process.command_line : (
  "*-EncodedCommand*", "*-enc *", "*-e *",
  "*IEX*", "*Invoke-Expression*",
  "*DownloadString*", "*DownloadFile*",
  "*Invoke-WebRequest*", "*Net.WebClient*",
  "*FromBase64String*", "*-w hidden*",
  "*bypass*", "*AmsiUtils*"
)`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Suspicious PowerShell Execution - T1059.001
id: a1b2c3d4-5678-90ab-cdef-123456789001
status: stable
description: Detects suspicious PowerShell execution patterns
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_encoded:
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
            - ' -e '
    selection_download:
        CommandLine|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'Invoke-WebRequest'
            - 'Net.WebClient'
    selection_obfuscation:
        CommandLine|contains:
            - 'FromBase64String'
            - '-w hidden'
            - 'bypass'
    condition: selection_process and (selection_encoded or selection_download or selection_obfuscation)
level: high
tags:
    - attack.execution
    - attack.t1059.001`
        }
      ]
    },
    // T1047 - Windows Management Instrumentation
    {
      id: "T1047",
      name: "WMI Execution",
      description: "Detects Windows Management Instrumentation (WMI) being used for execution and lateral movement.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where FileName =~ "wmic.exe" or InitiatingProcessFileName =~ "wmiprvse.exe"
| where ProcessCommandLine has_any ("process call create", "os get", "product get", "shadowcopy delete", "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688)
((Image="*\\wmic.exe" AND (CommandLine="*process call create*" OR CommandLine="*/node:*"))
OR (ParentImage="*\\wmiprvse.exe" AND (Image="*\\cmd.exe" OR Image="*\\powershell.exe")))
| stats count by Computer, User, Image, CommandLine, ParentImage`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, username, "Process CommandLine" as cmdline FROM events
WHERE ("Process Name" ILIKE '%wmic.exe'
AND ("Process CommandLine" ILIKE '%process call create%' OR "Process CommandLine" ILIKE '%/node:%'))
OR ("Parent Process Name" ILIKE '%wmiprvse.exe')
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `sequence by host.id with maxspan=30s
[process where process.name : "wmic.exe" and process.command_line : ("*process call create*", "*/node:*")]
[process where process.parent.name : "wmiprvse.exe"]`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: WMI Execution - T1047
id: b2c3d4e5-6789-0abc-def1-234567890002
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection_wmic:
        Image|endswith: '\\wmic.exe'
        CommandLine|contains:
            - 'process call create'
            - '/node:'
    selection_wmiprvse_child:
        ParentImage|endswith: '\\wmiprvse.exe'
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
    condition: selection_wmic or selection_wmiprvse_child
level: high
tags:
    - attack.execution
    - attack.t1047`
        }
      ]
    },
    // T1053.002 - At Job
    {
      id: "T1053.002",
      name: "At Job Execution",
      description: "Detects use of at.exe for scheduled execution.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where FileName =~ "at.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688) Image="*\\at.exe"
| stats count by Computer, User, CommandLine`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: At Job Execution - T1053.002
id: c3d4e5f6-7890-abcd-ef12-345678901234
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\at.exe'
    condition: selection
level: medium
tags:
    - attack.execution
    - attack.persistence
    - attack.t1053.002`
        }
      ]
    },
    // T1204.001 - Malicious Link
    {
      id: "T1204.001",
      name: "User Execution - Malicious Link",
      description: "Detects user clicking on malicious links leading to payload execution.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let browsers = dynamic(["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe"]);
let suspicious_children = dynamic(["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"]);
DeviceProcessEvents
| where InitiatingProcessFileName in~ (browsers)
| where FileName in~ (suspicious_children)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688)
ParentImage IN ("*\\chrome.exe", "*\\msedge.exe", "*\\firefox.exe", "*\\iexplore.exe")
Image IN ("*\\cmd.exe", "*\\powershell.exe", "*\\wscript.exe", "*\\mshta.exe", "*\\rundll32.exe")
| stats count by Computer, ParentImage, Image, CommandLine`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Browser Spawning Suspicious Process - T1204.001
id: d4e5f6a7-8901-bcde-f234-567890123456
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\chrome.exe'
            - '\\msedge.exe'
            - '\\firefox.exe'
            - '\\iexplore.exe'
    selection_child:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\wscript.exe'
            - '\\mshta.exe'
    condition: selection_parent and selection_child
level: high
tags:
    - attack.execution
    - attack.t1204.001`
        }
      ]
    },
    // T1204.002 - Malicious File
    {
      id: "T1204.002",
      name: "User Execution - Malicious File",
      description: "Detects Office applications spawning suspicious child processes.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let office_apps = dynamic(["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE", "MSACCESS.EXE"]);
let suspicious_children = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe"]);
DeviceProcessEvents
| where InitiatingProcessFileName in~ (office_apps)
| where FileName in~ (suspicious_children)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688)
ParentImage IN ("*\\WINWORD.EXE", "*\\EXCEL.EXE", "*\\POWERPNT.EXE", "*\\OUTLOOK.EXE")
Image IN ("*\\cmd.exe", "*\\powershell.exe", "*\\wscript.exe", "*\\mshta.exe", "*\\rundll32.exe", "*\\certutil.exe")
| stats count by Computer, ParentImage, Image, CommandLine`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, username, "Parent Process Name" as parent, "Process Name" as child, "Process CommandLine" as cmdline FROM events
WHERE ("Parent Process Name" ILIKE '%WINWORD.EXE' OR "Parent Process Name" ILIKE '%EXCEL.EXE' OR "Parent Process Name" ILIKE '%OUTLOOK.EXE')
AND ("Process Name" ILIKE '%cmd.exe' OR "Process Name" ILIKE '%powershell.exe' OR "Process Name" ILIKE '%wscript.exe' OR "Process Name" ILIKE '%mshta.exe')
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `process where event.type == "start" and
process.parent.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE") and
process.name : ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "certutil.exe")`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Office Application Spawning Suspicious Process - T1204.002
id: e5f6a7b8-9012-cdef-3456-789012345678
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\WINWORD.EXE'
            - '\\EXCEL.EXE'
            - '\\POWERPNT.EXE'
            - '\\OUTLOOK.EXE'
    selection_child:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\wscript.exe'
            - '\\mshta.exe'
            - '\\rundll32.exe'
            - '\\certutil.exe'
    condition: selection_parent and selection_child
level: critical
tags:
    - attack.execution
    - attack.t1204.002`
        }
      ]
    },
    // T1218.011 - Rundll32
    {
      id: "T1218.011",
      name: "Rundll32 Abuse",
      description: "Detects suspicious rundll32.exe usage for proxy execution.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("javascript:", "vbscript:", "shell32.dll,Control_RunDLL", "url.dll,FileProtocolHandler", "advpack.dll,LaunchINFSection", "ieframe.dll,OpenURL", "\\\\", "http://", "https://")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688) Image="*\\rundll32.exe"
(CommandLine="*javascript:*" OR CommandLine="*vbscript:*" OR CommandLine="*shell32.dll,Control_RunDLL*"
OR CommandLine="*url.dll*" OR CommandLine="*\\\\*" OR CommandLine="*http://*" OR CommandLine="*https://*")
| stats count by Computer, User, CommandLine, ParentImage`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Suspicious Rundll32 Execution - T1218.011
id: f6a7b8c9-0123-def4-5678-901234567890
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\rundll32.exe'
    suspicious:
        CommandLine|contains:
            - 'javascript:'
            - 'vbscript:'
            - 'shell32.dll,Control_RunDLL'
            - 'url.dll,FileProtocolHandler'
            - 'http://'
            - 'https://'
    condition: selection and suspicious
level: high
tags:
    - attack.defense_evasion
    - attack.t1218.011`
        }
      ]
    },
    // T1218.010 - Regsvr32
    {
      id: "T1218.010",
      name: "Regsvr32 Abuse (Squiblydoo)",
      description: "Detects regsvr32.exe used for proxy execution or scriptlet loading.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has_any ("/s", "/i", "scrobj.dll", "http://", "https://", "/u", ".sct")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688) Image="*\\regsvr32.exe"
(CommandLine="*/s*" AND (CommandLine="*/i*" OR CommandLine="*scrobj.dll*" OR CommandLine="*http*" OR CommandLine="*.sct*"))
| stats count by Computer, User, CommandLine, ParentImage`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Regsvr32 Scriptlet Execution - T1218.010
id: a7b8c9d0-1234-ef56-7890-123456789012
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\regsvr32.exe'
    suspicious:
        CommandLine|contains:
            - '/i:'
            - 'scrobj.dll'
            - '.sct'
            - 'http://'
            - 'https://'
    condition: selection and suspicious
level: high
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218.010`
        }
      ]
    },
    // T1218.005 - Mshta
    {
      id: "T1218.005",
      name: "Mshta Abuse",
      description: "Detects mshta.exe used for HTA or inline script execution.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any ("javascript:", "vbscript:", "http://", "https://", ".hta", "about:")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688) Image="*\\mshta.exe"
(CommandLine="*javascript:*" OR CommandLine="*vbscript:*" OR CommandLine="*http*" OR CommandLine="*.hta*" OR CommandLine="*about:*")
| stats count by Computer, User, CommandLine, ParentImage`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Mshta Suspicious Execution - T1218.005
id: b8c9d0e1-2345-f678-9012-345678901234
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\mshta.exe'
    suspicious:
        CommandLine|contains:
            - 'javascript:'
            - 'vbscript:'
            - 'http://'
            - 'https://'
            - '.hta'
    condition: selection and suspicious
level: high
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218.005`
        }
      ]
    }
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
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=4698 OR EventCode=4699 OR EventCode=4702)
| stats count values(TaskName) as tasks by Computer, SubjectUserName, EventCode`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Scheduled Task Created - T1053.005
id: c9d0e1f2-3456-7890-abcd-ef1234567890
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4698
            - 4699
    condition: selection
level: medium
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1053.005`
        }
      ]
    },
    // T1543.003 - Windows Service
    {
      id: "T1543.003",
      name: "Windows Service Creation",
      description: "Detects creation of Windows services which can be used for persistence.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `SecurityEvent
| where EventID == 4697
| project TimeGenerated, Computer, SubjectUserName, ServiceName, ServiceFileName, ServiceStartType
| extend SuspiciousPath = ServiceFileName has_any ("\\temp\\", "\\appdata\\", "\\programdata\\", "cmd.exe", "powershell.exe")`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=4697 OR EventCode=7045)
| eval suspicious=if(match(ServiceFileName, "(?i)(\\\\temp\\\\|\\\\appdata\\\\|cmd\\.exe|powershell\\.exe)"), 1, 0)
| stats count values(ServiceName) as services values(ServiceFileName) as paths by Computer, suspicious`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, username, "Service Name" as service, "Service File Name" as path FROM events
WHERE "EventID" IN ('4697', '7045')
LAST 24 HOURS`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Service Installation - T1543.003
id: d0e1f2a3-4567-890a-bcde-f12345678901
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4697
            - 7045
    suspicious_paths:
        ServiceFileName|contains:
            - '\\Temp\\'
            - '\\AppData\\'
            - 'cmd.exe'
            - 'powershell.exe'
    condition: selection and suspicious_paths
level: high
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1543.003`
        }
      ]
    },
    // T1546.001 - Change Default File Association
    {
      id: "T1546.001",
      name: "Change Default File Association",
      description: "Detects modification of file associations for persistence.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceRegistryEvents
| where RegistryKey has_any ("Classes\\\\.", "\\\\shell\\\\open\\\\command")
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=13)
TargetObject="*\\Classes\\*\\shell\\open\\command*"
| stats count values(Details) as commands by Computer, TargetObject`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: File Association Change - T1546.001
id: e1f2a3b4-5678-901a-bcde-f23456789012
status: stable
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\\Classes\\'
            - '\\shell\\open\\command'
    condition: selection
level: medium
tags:
    - attack.persistence
    - attack.t1546.001`
        }
      ]
    },
    // T1136.001 - Local Account Creation
    {
      id: "T1136.001",
      name: "Local Account Creation",
      description: "Detects creation of local user accounts.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `SecurityEvent
| where EventID == 4720
| project TimeGenerated, Computer, TargetUserName, SubjectUserName, TargetDomainName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows EventCode=4720
| stats count by Computer, TargetUserName, SubjectUserName`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT * FROM events WHERE "EventID" = '4720' LAST 24 HOURS`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Local Account Creation - T1136.001
id: f2a3b4c5-6789-012b-cdef-345678901234
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
    condition: selection
level: medium
tags:
    - attack.persistence
    - attack.t1136.001`
        }
      ]
    },
    // T1098 - Account Manipulation
    {
      id: "T1098",
      name: "Account Manipulation",
      description: "Detects account modifications including group membership changes.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `SecurityEvent
| where EventID in (4728, 4732, 4756, 4738)
| project TimeGenerated, Computer, EventID, Activity, TargetUserName, MemberName, SubjectUserName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows EventCode IN (4728, 4732, 4756, 4738)
| stats count values(MemberName) as members by Computer, EventCode, TargetUserName`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT * FROM events
WHERE "EventID" IN ('4728', '4732', '4756', '4738')
LAST 24 HOURS`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Account Manipulation - T1098
id: a3b4c5d6-7890-123c-def4-567890123456
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4728
            - 4732
            - 4756
            - 4738
    condition: selection
level: medium
tags:
    - attack.persistence
    - attack.t1098`
        }
      ]
    },
    // T1505.003 - Web Shell
    {
      id: "T1505.003",
      name: "Web Shell",
      description: "Detects web shell activity on IIS/Apache/Nginx servers.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "net1.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688)
ParentImage IN ("*\\w3wp.exe", "*\\httpd.exe", "*\\nginx.exe", "*\\php-cgi.exe")
Image IN ("*\\cmd.exe", "*\\powershell.exe", "*\\whoami.exe", "*\\net.exe")
| stats count by Computer, ParentImage, Image, CommandLine`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, "Parent Process Name" as parent, "Process Name" as child, "Process CommandLine" as cmdline FROM events
WHERE ("Parent Process Name" ILIKE '%w3wp.exe' OR "Parent Process Name" ILIKE '%httpd.exe')
AND ("Process Name" ILIKE '%cmd.exe' OR "Process Name" ILIKE '%powershell.exe')
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `process where event.type == "start" and
process.parent.name : ("w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe") and
process.name : ("cmd.exe", "powershell.exe", "whoami.exe", "net.exe")`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Web Shell Detection - T1505.003
id: b4c5d6e7-8901-234d-ef56-789012345678
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\w3wp.exe'
            - '\\httpd.exe'
            - '\\nginx.exe'
            - '\\php-cgi.exe'
    selection_child:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\whoami.exe'
            - '\\net.exe'
    condition: selection_parent and selection_child
level: critical
tags:
    - attack.persistence
    - attack.t1505.003`
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
    },
    {
      id: "T1548.002",
      name: "Bypass User Account Control (UAC)",
      description: "Detects UAC bypass techniques using fodhelper, eventvwr, computerdefaults, and registry hijacking.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let UACBypassProcs = dynamic(["fodhelper.exe", "eventvwr.exe", "computerdefaults.exe", "sdclt.exe", "slui.exe"]);
let SuspiciousChildren = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe"]);
union (
    DeviceProcessEvents
    | where InitiatingProcessFileName in~ (UACBypassProcs)
    | where FileName in~ (SuspiciousChildren)
    | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
),
(
    DeviceRegistryEvents
    | where RegistryKey has_any ("ms-settings\\\\Shell\\\\Open\\\\command", "mscfile\\\\Shell\\\\Open\\\\command")
    | project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueData
)`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows ((EventCode=1 OR EventCode=4688) (ParentImage="*fodhelper.exe" OR ParentImage="*eventvwr.exe" OR ParentImage="*computerdefaults.exe" OR ParentImage="*sdclt.exe") (Image="*cmd.exe" OR Image="*powershell.exe" OR Image="*mshta.exe"))
OR (EventCode=13 (TargetObject="*ms-settings\\Shell\\Open\\command*" OR TargetObject="*mscfile\\Shell\\Open\\command*"))
| stats count by Computer, User, ParentImage, Image, CommandLine, TargetObject`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, username, "Parent Image" as parent, "Image" as process, "Process CommandLine" as cmdline FROM events
WHERE (("Parent Image" ILIKE '%fodhelper.exe' OR "Parent Image" ILIKE '%eventvwr.exe' OR "Parent Image" ILIKE '%computerdefaults.exe')
AND ("Image" ILIKE '%cmd.exe' OR "Image" ILIKE '%powershell.exe' OR "Image" ILIKE '%mshta.exe'))
OR ("TargetObject" ILIKE '%ms-settings\\Shell\\Open\\command%')
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `sequence by host.id with maxspan=1m
[registry where registry.path : ("*\\\\ms-settings\\\\Shell\\\\Open\\\\command\\\\*", "*\\\\mscfile\\\\Shell\\\\Open\\\\command\\\\*")]
[process where event.type == "start" and process.parent.name : ("fodhelper.exe", "eventvwr.exe", "computerdefaults.exe", "sdclt.exe") and
process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe")]`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: UAC Bypass via Auto-Elevating Executables - T1548.002
id: 7e8f9a0b-1c2d-3e4f-5a6b-7c8d9e0f1a2b
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\\fodhelper.exe'
            - '\\eventvwr.exe'
            - '\\computerdefaults.exe'
            - '\\sdclt.exe'
    selection_child:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\mshta.exe'
    condition: selection_parent and selection_child
level: high
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1548.002`
        }
      ]
    },
    {
      id: "T1134.001",
      name: "Access Token Manipulation - Token Impersonation",
      description: "Detects token impersonation and theft using DuplicateToken, CreateProcessWithToken, and known tools like Mimikatz.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let TokenManipulationTools = dynamic(["mimikatz", "incognito", "tokenvator", "PrintSpoofer", "JuicyPotato", "SweetPotato", "GodPotato"]);
let TokenAPIs = dynamic(["DuplicateToken", "ImpersonateLoggedOnUser", "SetThreadToken", "CreateProcessWithToken", "token::", "privilege::debug"]);
DeviceProcessEvents
| where ProcessCommandLine has_any (TokenManipulationTools) or ProcessCommandLine has_any (TokenAPIs)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688)
(CommandLine="*DuplicateToken*" OR CommandLine="*ImpersonateLoggedOnUser*" OR CommandLine="*SetThreadToken*"
OR CommandLine="*CreateProcessWithToken*" OR CommandLine="*token::*" OR CommandLine="*privilege::debug*"
OR CommandLine="*mimikatz*" OR CommandLine="*PrintSpoofer*" OR CommandLine="*JuicyPotato*")
| stats count by Computer, User, ParentImage, Image, CommandLine`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, username, "Image" as process, "Process CommandLine" as cmdline FROM events
WHERE ("Process CommandLine" ILIKE '%DuplicateToken%' OR "Process CommandLine" ILIKE '%ImpersonateLoggedOnUser%'
OR "Process CommandLine" ILIKE '%token::%' OR "Process CommandLine" ILIKE '%privilege::debug%'
OR "Process CommandLine" ILIKE '%mimikatz%' OR "Process CommandLine" ILIKE '%PrintSpoofer%')
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `process where event.type == "start" and process.command_line : ("*DuplicateToken*", "*ImpersonateLoggedOnUser*", "*SetThreadToken*",
"*CreateProcessWithToken*", "*token::*", "*privilege::debug*", "*mimikatz*", "*PrintSpoofer*", "*JuicyPotato*")`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Token Impersonation Detection - T1134.001
id: 3a4b5c6d-7e8f-9a0b-1c2d-3e4f5a6b7c8d
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_api:
        CommandLine|contains:
            - 'DuplicateToken'
            - 'ImpersonateLoggedOnUser'
            - 'SetThreadToken'
            - 'CreateProcessWithToken'
    selection_mimikatz:
        CommandLine|contains:
            - 'token::'
            - 'privilege::debug'
    selection_tools:
        CommandLine|contains:
            - 'mimikatz'
            - 'PrintSpoofer'
            - 'JuicyPotato'
    condition: selection_api or selection_mimikatz or selection_tools
level: high
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1134.001`
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
},
{
  id: "T1055.002",
  name: "Portable Executable Injection",
  description: "Detects PE injection via WriteProcessMemory and VirtualAllocEx targeting remote processes.",
  rules: [
    {
      type: "Sentinel KQL",
      lang: "sentinel",
      code: `let suspiciousTargets = dynamic(["explorer.exe", "svchost.exe", "notepad.exe", "iexplore.exe"]);
DeviceEvents
| where ActionType in ("CreateRemoteThreadApiCall", "WriteToRemoteProcess")
| extend TargetFileName = tostring(split(TargetProcessFileName, "\\\\")[-1])
| where TargetFileName in~ (suspiciousTargets)
| project Timestamp, DeviceName, InitiatingProcessFileName, TargetProcessFileName, ActionType, AccountName`
    },
    {
      type: "Splunk SPL",
      lang: "splunk",
      code: `index=sysmon (EventCode=8 OR EventCode=10)
| where SourceImage!=TargetImage
| search TargetImage IN ("*explorer.exe", "*svchost.exe", "*notepad.exe")
| stats count values(SourceImage) as SourceProcesses by Computer, TargetImage`
    },
    {
      type: "QRadar AQL",
      lang: "qradar",
      code: `SELECT sourceip, "SourceImage" AS source_process, "TargetImage" AS target_process, "GrantedAccess" AS access_mask FROM events
WHERE ("EventID" = '8' OR "EventID" = '10') AND "SourceImage" <> "TargetImage"
AND ("TargetImage" ILIKE '%explorer.exe' OR "TargetImage" ILIKE '%svchost.exe')
LAST 24 HOURS`
    },
    {
      type: "Elastic EQL",
      lang: "elastic",
      code: `any where event.code == "8" and process.Ext.api.name : ("VirtualAllocEx", "WriteProcessMemory") and
process.Ext.api.parameters.protection : ("*RWX*", "*EXECUTE_READWRITE*")`
    },
    {
      type: "Sigma",
      lang: "sigma",
      code: `title: PE Injection via WriteProcessMemory - T1055.002
id: f5a7b3c1-2d4e-5f6a-8b9c-0d1e2f3a4b5c
status: experimental
logsource:
    category: create_remote_thread
    product: windows
detection:
    selection:
        EventID: 8
    suspicious_target:
        TargetImage|endswith:
            - '\\explorer.exe'
            - '\\svchost.exe'
            - '\\notepad.exe'
    condition: selection and suspicious_target
level: high
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1055.002`
    }
  ]
},
{
  id: "T1055.003",
  name: "Thread Execution Hijacking",
  description: "Detects thread hijacking via SuspendThread, SetThreadContext, and ResumeThread API sequence.",
  rules: [
    {
      type: "Sentinel KQL",
      lang: "sentinel",
      code: `let threadHijackAPIs = dynamic(["SetThreadContext", "NtSetContextThread", "SuspendThread", "ResumeThread"]);
DeviceEvents
| where ActionType == "SetThreadContext" or ActionType has_any (threadHijackAPIs)
| where InitiatingProcessFileName != TargetProcessFileName
| project Timestamp, DeviceName, InitiatingProcessFileName, TargetProcessFileName, ActionType, AccountName`
    },
    {
      type: "Splunk SPL",
      lang: "splunk",
      code: `index=sysmon (EventCode=10)
| where SourceImage!=TargetImage
| search GrantedAccess IN ("0x800", "0x801", "0x80a", "0x1f0fff", "0x1fffff")
| stats count dc(TargetImage) as UniqueTargets values(TargetImage) as TargetProcesses by Computer, SourceImage`
    },
    {
      type: "QRadar AQL",
      lang: "qradar",
      code: `SELECT sourceip, "SourceImage" AS source_process, "TargetImage" AS target_process, "GrantedAccess" AS access_mask FROM events
WHERE "EventID" = '10' AND "SourceImage" <> "TargetImage"
AND ("GrantedAccess" ILIKE '%800%' OR "GrantedAccess" ILIKE '%1f0fff%')
LAST 24 HOURS`
    },
    {
      type: "Elastic EQL",
      lang: "elastic",
      code: `sequence by host.id, process.entity_id with maxspan=30s
[api where process.Ext.api.name == "SuspendThread"]
[api where process.Ext.api.name : ("SetThreadContext", "NtSetContextThread")]
[api where process.Ext.api.name : ("ResumeThread", "NtResumeThread")]`
    },
    {
      type: "Sigma",
      lang: "sigma",
      code: `title: Thread Execution Hijacking - T1055.003
id: a8c9d2e3-4f5a-6b7c-8d9e-0f1a2b3c4d5e
status: experimental
logsource:
    category: process_access
    product: windows
detection:
    selection:
        EventID: 10
    access_rights:
        GrantedAccess|contains:
            - '0x800'
            - '0x1f0fff'
    filter_self:
        SourceImage: TargetImage
    condition: selection and access_rights and not filter_self
level: high
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1055.003`
    }
  ]
},
{
  id: "T1055.012",
  name: "Process Hollowing",
  description: "Detects process hollowing via suspicious process creation with empty command line and abnormal parent-child relationships.",
  rules: [
    {
      type: "Sentinel KQL",
      lang: "sentinel",
      code: `let legitimateParents = dynamic(["services.exe", "svchost.exe", "wininit.exe", "smss.exe"]);
let hollowTargets = dynamic(["svchost.exe", "RuntimeBroker.exe", "dllhost.exe", "regsvr32.exe"]);
DeviceProcessEvents
| extend ParentFileName = tostring(split(InitiatingProcessFileName, "\\\\")[-1])
| where FileName in~ (hollowTargets)
| where ParentFileName !in~ (legitimateParents)
| where ProcessCommandLine == "" or ProcessCommandLine == FileName
| project Timestamp, DeviceName, ParentFileName, FileName, ProcessCommandLine, AccountName`
    },
    {
      type: "Splunk SPL",
      lang: "splunk",
      code: `index=sysmon EventCode=1
| where match(Image, "(?i)(svchost|runtimebroker|dllhost|regsvr32)\\.exe$")
| where NOT match(ParentImage, "(?i)(services|svchost|wininit|smss)\\.exe$")
| where isnull(CommandLine) OR CommandLine="" OR CommandLine=Image
| stats count values(Image) as HollowedProcesses by Computer, ParentImage`
    },
    {
      type: "QRadar AQL",
      lang: "qradar",
      code: `SELECT sourceip, username, "ParentImage" AS parent_process, "Image" AS target_process, "CommandLine" AS command_line FROM events
WHERE "EventID" = '1'
AND ("Image" ILIKE '%svchost.exe' OR "Image" ILIKE '%RuntimeBroker.exe' OR "Image" ILIKE '%dllhost.exe')
AND NOT ("ParentImage" ILIKE '%services.exe' OR "ParentImage" ILIKE '%svchost.exe' OR "ParentImage" ILIKE '%wininit.exe')
AND ("CommandLine" IS NULL OR "CommandLine" = '')
LAST 24 HOURS`
    },
    {
      type: "Elastic EQL",
      lang: "elastic",
      code: `process where event.type == "start" and
process.name : ("svchost.exe", "RuntimeBroker.exe", "dllhost.exe", "regsvr32.exe") and
not process.parent.name : ("services.exe", "svchost.exe", "wininit.exe") and
process.args_count == 0`
    },
    {
      type: "Sigma",
      lang: "sigma",
      code: `title: Process Hollowing - T1055.012
id: b9d0e1f2-3a4b-5c6d-7e8f-9a0b1c2d3e4f
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith:
            - '\\svchost.exe'
            - '\\RuntimeBroker.exe'
            - '\\dllhost.exe'
            - '\\regsvr32.exe'
    filter_legitimate_parent:
        ParentImage|endswith:
            - '\\services.exe'
            - '\\svchost.exe'
            - '\\wininit.exe'
    suspicious_cmdline:
        CommandLine: ''
    condition: selection_process and suspicious_cmdline and not filter_legitimate_parent
level: critical
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1055.012`
    }
  ]
}
   ],
   
 
  // ======================
  // TA0008 – Lateral Movement
  // ======================
  "TA0008": [
    {
      id: "T1021.002",
      name: "SMB/Windows Admin Shares Lateral Movement",
      description: "Detects lateral movement via SMB admin shares (C$, ADMIN$, IPC$) and PsExec execution.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let AdminShares = dynamic(["C$", "ADMIN$", "IPC$"]);
SecurityEvent
| where EventID in (5140, 5145)
| where ShareName has_any (AdminShares)
| where SubjectUserName !endswith "$"
| summarize Count = count() by Computer, SubjectUserName, ShareName, IpAddress, bin(TimeGenerated, 1h)`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows ((EventCode=5140 OR EventCode=5145) (ShareName="*C$*" OR ShareName="*ADMIN$*" OR ShareName="*IPC$*"))
OR (EventCode=4688 (CommandLine="*psexec*" OR Image="*\\psexec.exe"))
OR (EventCode=7045 ServiceName="PSEXESVC")
| stats count by Computer, user, ShareName, src_ip, CommandLine`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, destinationip, username, "ShareName" as share FROM events
WHERE ("EventID" IN ('5140', '5145') AND ("ShareName" ILIKE '%C$%' OR "ShareName" ILIKE '%ADMIN$%'))
OR ("Process CommandLine" ILIKE '%psexec%')
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `any where (event.code in ("5140", "5145") and winlog.event_data.ShareName : ("*C$*", "*ADMIN$*", "*IPC$*"))
or (process.name : ("psexec.exe", "PsExec64.exe") or process.command_line : "*psexec*")`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: SMB Admin Shares and PsExec Lateral Movement - T1021.002
id: f8a7b9c2-3d4e-5f6a-7b8c-9d0e1f2a3b4c
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection_share:
        EventID:
            - 5140
            - 5145
        ShareName|contains:
            - 'C$'
            - 'ADMIN$'
    selection_psexec:
        EventID: 4688
        NewProcessName|endswith: '\\psexec.exe'
    condition: selection_share or selection_psexec
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.002`
        }
      ]
    },
    {
      id: "T1021.004",
      name: "SSH Lateral Movement",
      description: "Detects SSH-based lateral movement including brute force attempts and unusual SSH client/server activity on Windows.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let SSHProcesses = dynamic(["ssh.exe", "sshd.exe", "putty.exe", "plink.exe"]);
union (
    SecurityEvent
    | where EventID == 4625 and LogonType == 3
    | summarize FailedAttempts=count() by IpAddress, Computer, bin(TimeGenerated, 5m)
    | where FailedAttempts > 10
),
(
    DeviceProcessEvents
    | where FileName has_any (SSHProcesses)
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
),
(
    DeviceNetworkEvents
    | where RemotePort == 22 or LocalPort == 22
    | project Timestamp, DeviceName, RemoteIP, LocalPort, RemotePort
)`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows ((EventCode=4625 LogonType=3) OR (EventCode=4688 (Image="*\\ssh.exe" OR Image="*\\sshd.exe" OR Image="*\\putty.exe" OR Image="*\\plink.exe")) OR (EventCode=5156 DestPort=22))
| bucket _time span=5m
| stats count as attempts values(Image) as processes by src_ip, dest, _time
| where attempts > 10 OR isnotnull(processes)`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, destinationip, username, destinationport, "Process Name" as process FROM events
WHERE ("EventID" = '4625' AND "LogonType" = '3')
OR ("Process Name" ILIKE '%ssh.exe' OR "Process Name" ILIKE '%putty.exe' OR "Process Name" ILIKE '%plink.exe')
OR (destinationport = 22)
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `any where (event.code == "4625" and winlog.event_data.LogonType == "3")
or (event.type == "start" and process.name : ("ssh.exe", "sshd.exe", "putty.exe", "plink.exe"))
or (event.category == "network" and destination.port == 22)`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: SSH Lateral Movement Detection - T1021.004
id: a9b8c7d6-5e4f-3a2b-1c0d-9e8f7a6b5c4d
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection_ssh_process:
        EventID: 4688
        NewProcessName|endswith:
            - '\\ssh.exe'
            - '\\sshd.exe'
            - '\\putty.exe'
            - '\\plink.exe'
    selection_ssh_connection:
        EventID: 5156
        DestPort: 22
    condition: selection_ssh_process or selection_ssh_connection
level: medium
tags:
    - attack.lateral_movement
    - attack.t1021.004`
        }
      ]
    },
    {
      id: "T1021.006",
      name: "Windows Remote Management (WinRM) Abuse",
      description: "Detects WinRM-based remote execution including Enter-PSSession, Invoke-Command, and wsmprovhost execution.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let WinRMCommands = dynamic(["Enter-PSSession", "Invoke-Command", "New-PSSession", "New-CimSession"]);
union (
    DeviceProcessEvents
    | where ProcessCommandLine has_any (WinRMCommands)
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
),
(
    DeviceProcessEvents
    | where FileName =~ "wsmprovhost.exe"
    | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
),
(
    DeviceNetworkEvents
    | where RemotePort in (5985, 5986) or LocalPort in (5985, 5986)
    | project Timestamp, DeviceName, RemoteIP, InitiatingProcessFileName
)`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows ((EventCode=4688 (CommandLine="*Enter-PSSession*" OR CommandLine="*Invoke-Command*" OR CommandLine="*New-PSSession*" OR CommandLine="*-ComputerName*"))
OR (EventCode=4688 Image="*\\wsmprovhost.exe")
OR (EventCode=5156 (DestPort=5985 OR DestPort=5986)))
| stats count values(CommandLine) as commands by Computer, user, src_ip`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, destinationip, username, "Process CommandLine" as cmdline FROM events
WHERE ("Process CommandLine" ILIKE '%Enter-PSSession%' OR "Process CommandLine" ILIKE '%Invoke-Command%' OR "Process CommandLine" ILIKE '%New-PSSession%')
OR ("Process Name" ILIKE '%wsmprovhost%')
OR (destinationport IN (5985, 5986))
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `any where (event.code == "4688" and process.command_line : ("*Enter-PSSession*", "*Invoke-Command*", "*New-PSSession*"))
or (process.name : "wsmprovhost.exe")
or (event.category == "network" and destination.port in (5985, 5986))`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: WinRM Abuse Detection - T1021.006
id: c1d2e3f4-5a6b-7c8d-9e0f-1a2b3c4d5e6f
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection_ps_remoting:
        EventID: 4688
        CommandLine|contains:
            - 'Enter-PSSession'
            - 'Invoke-Command'
            - 'New-PSSession'
    selection_wsmprovhost:
        EventID: 4688
        NewProcessName|endswith: '\\wsmprovhost.exe'
    selection_winrm_network:
        EventID: 5156
        DestPort:
            - 5985
            - 5986
    condition: selection_ps_remoting or selection_wsmprovhost or selection_winrm_network
level: medium
tags:
    - attack.lateral_movement
    - attack.t1021.006`
        }
      ]
    },
    {
      id: "T1570",
      name: "Lateral Tool Transfer",
      description: "Detects lateral tool transfer via SMB shares, PsExec file copies, and internal staging patterns.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let suspiciousExtensions = dynamic([".exe", ".dll", ".ps1", ".bat", ".vbs"]);
SecurityEvent
| where EventID in (5140, 5145)
| where ShareName has_any ("C$", "ADMIN$")
| where ObjectName has_any (suspiciousExtensions)
| where SubjectUserName !endswith "$"
| project TimeGenerated, Computer, SubjectUserName, ShareName, ObjectName, IpAddress`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows ((EventCode=5140 OR EventCode=5145) (ShareName="*C$*" OR ShareName="*ADMIN$*") (ObjectName="*.exe" OR ObjectName="*.dll" OR ObjectName="*.ps1" OR ObjectName="*.bat"))
OR (EventCode=1 (Image="*psexec*" OR CommandLine="*psexec*") (CommandLine="*-c*" OR CommandLine="*/c*"))
| stats count by Computer, user, ShareName, ObjectName, CommandLine`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, destinationip, username, "ShareName" as share, "ObjectName" as object FROM events
WHERE (("EventID" IN ('5140', '5145') AND ("ShareName" ILIKE '%C$%' OR "ShareName" ILIKE '%ADMIN$%') AND ("ObjectName" ILIKE '%.exe' OR "ObjectName" ILIKE '%.dll' OR "ObjectName" ILIKE '%.ps1')))
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `file where event.action == "creation" and file.path : ("*\\\\C$\\\\*", "*\\\\ADMIN$\\\\*") and
file.extension : ("exe", "dll", "ps1", "bat", "vbs")`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Lateral Tool Transfer - T1570
id: a1b2c3d4-5678-90ab-cdef-123456789abc
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection_smb:
        EventID:
            - 5140
            - 5145
        ShareName|contains:
            - 'C$'
            - 'ADMIN$'
        ObjectName|endswith:
            - '.exe'
            - '.dll'
            - '.ps1'
    condition: selection_smb
level: high
tags:
    - attack.lateral_movement
    - attack.t1570`
        }
      ]
    },
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

  // ======================
  // TA0009 – Collection
  // ======================
  "TA0009": [
    // T1113 - Screen Capture
    {
      id: "T1113",
      name: "Screen Capture",
      description: "Detects screen capture utilities and screenshot tools that could be used for data collection.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where FileName in~ ("snippingtool.exe", "psr.exe", "screengrab.exe")
    or ProcessCommandLine has_any ("Get-Screenshot", "CopyFromScreen", "BitBlt", "[System.Windows.Forms.Screen]")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688)
(Image="*\\psr.exe" OR Image="*\\snippingtool.exe"
OR CommandLine="*CopyFromScreen*" OR CommandLine="*Get-Screenshot*" OR CommandLine="*BitBlt*")
| stats count by Computer, User, Image, CommandLine`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Screen Capture Activity - T1113
id: a1b2c3d4-5678-90ab-cdef-000000000113
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        Image|endswith:
            - '\\psr.exe'
            - '\\snippingtool.exe'
    selection_powershell:
        CommandLine|contains:
            - 'CopyFromScreen'
            - 'Get-Screenshot'
    condition: selection_tools or selection_powershell
level: medium
tags:
    - attack.collection
    - attack.t1113`
        }
      ]
    },
    // T1056.001 - Keylogging
    {
      id: "T1056.001",
      name: "Keylogging",
      description: "Detects keylogger activity through SetWindowsHookEx, GetAsyncKeyState, and known keylogger tools.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where ProcessCommandLine has_any ("SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState", "keylog", "keystroke")
    or FileName in~ ("keylogger.exe", "hawkeye.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688)
(CommandLine="*SetWindowsHookEx*" OR CommandLine="*GetAsyncKeyState*" OR CommandLine="*keylog*")
| stats count by Computer, User, Image, CommandLine`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Keylogging Activity Detection - T1056.001
id: b2c3d4e5-6789-01ab-cdef-000000056001
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'SetWindowsHookEx'
            - 'GetAsyncKeyState'
            - 'GetKeyboardState'
            - 'keylog'
    condition: selection
level: high
tags:
    - attack.collection
    - attack.credential_access
    - attack.t1056.001`
        }
      ]
    },
    // T1560.001 - Archive Collected Data
    {
      id: "T1560.001",
      name: "Archive via Utility",
      description: "Detects compression of data before exfiltration using common archive utilities.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where FileName in~ ("7z.exe", "7za.exe", "rar.exe", "winrar.exe", "zip.exe", "tar.exe")
    or (FileName =~ "powershell.exe" and ProcessCommandLine has_any ("Compress-Archive", "ZipFile", "GZipStream"))
| where ProcessCommandLine has_any ("-p", "-password", "Documents", "Desktop", ".doc", ".xls", ".pdf", ".txt")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688)
(Image IN ("*\\7z.exe", "*\\7za.exe", "*\\rar.exe", "*\\winrar.exe")
OR (Image="*\\powershell.exe" AND (CommandLine="*Compress-Archive*" OR CommandLine="*ZipFile*")))
AND (CommandLine="*Documents*" OR CommandLine="*Desktop*" OR CommandLine="*.doc*" OR CommandLine="*.xls*")
| stats count by Computer, User, Image, CommandLine`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, username, "Process Name" as proc, "Process CommandLine" as cmdline FROM events
WHERE ("Process Name" ILIKE '%7z%' OR "Process Name" ILIKE '%rar%' OR "Process Name" ILIKE '%zip%')
AND ("Process CommandLine" ILIKE '%Documents%' OR "Process CommandLine" ILIKE '%.doc%')
LAST 24 HOURS`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Archive Creation for Exfiltration - T1560.001
id: c3d4e5f6-7890-12bc-def0-000000560001
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection_archive:
        Image|endswith:
            - '\\7z.exe'
            - '\\7za.exe'
            - '\\rar.exe'
            - '\\winrar.exe'
    selection_sensitive:
        CommandLine|contains:
            - 'Documents'
            - 'Desktop'
            - '.doc'
            - '.xls'
            - '.pdf'
    condition: selection_archive and selection_sensitive
level: medium
tags:
    - attack.collection
    - attack.exfiltration
    - attack.t1560.001`
        }
      ]
    },
    // T1074.001 - Local Data Staging
    {
      id: "T1074.001",
      name: "Local Data Staging",
      description: "Detects data being staged in common locations before exfiltration.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceFileEvents
| where ActionType == "FileCreated" or ActionType == "FileModified"
| where FolderPath has_any ("\\Temp\\", "\\ProgramData\\", "\\Public\\")
| where FileName endswith_cs ".zip" or FileName endswith_cs ".rar" or FileName endswith_cs ".7z"
| summarize FileCount = count(), Files = make_set(FileName) by DeviceName, FolderPath, bin(Timestamp, 1h)
| where FileCount > 5`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=sysmon EventCode=11
(TargetFilename="*\\Temp\\*" OR TargetFilename="*\\ProgramData\\*" OR TargetFilename="*\\Public\\*")
(TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z")
| stats count values(TargetFilename) as files by Computer, _time span=1h
| where count > 5`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Local Data Staging - T1074.001
id: d4e5f6a7-8901-23cd-ef01-000000074001
status: stable
logsource:
    category: file_event
    product: windows
detection:
    selection_path:
        TargetFilename|contains:
            - '\\Temp\\'
            - '\\ProgramData\\'
            - '\\Public\\'
    selection_archive:
        TargetFilename|endswith:
            - '.zip'
            - '.rar'
            - '.7z'
    condition: selection_path and selection_archive
level: medium
tags:
    - attack.collection
    - attack.t1074.001`
        }
      ]
    },
    // T1005 - Data from Local System
    {
      id: "T1005",
      name: "Data from Local System",
      description: "Detects access to sensitive local files and directories.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceFileEvents
| where ActionType == "FileRead" or ActionType == "FileAccessed"
| where FileName has_any (".kdbx", ".key", "id_rsa", "id_dsa", "wallet.dat", ".pfx", ".p12")
    or FolderPath has_any ("\\ssh\\", "\\.gnupg\\", "\\Bitcoin\\")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=sysmon EventCode=11
(TargetFilename="*.kdbx" OR TargetFilename="*id_rsa*" OR TargetFilename="*wallet.dat*"
OR TargetFilename="*.pfx" OR TargetFilename="*.p12"
OR TargetFilename="*\\.ssh\\*" OR TargetFilename="*\\.gnupg\\*")
| stats count values(TargetFilename) as files by Computer, Image`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Sensitive File Access - T1005
id: e5f6a7b8-9012-34de-f012-000000001005
status: stable
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|contains:
            - '.kdbx'
            - 'id_rsa'
            - 'wallet.dat'
            - '.pfx'
            - '.p12'
            - '\\.ssh\\'
    condition: selection
level: high
tags:
    - attack.collection
    - attack.t1005`
        }
      ]
    },
    // T1039 - Data from Network Shared Drive
    {
      id: "T1039",
      name: "Data from Network Shared Drive",
      description: "Detects bulk access to files on network shares.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `SecurityEvent
| where EventID == 5145
| where ShareName contains "$" == false
| summarize FileAccessCount = count(), UniqueFiles = dcount(ObjectName) by SubjectUserName, ShareName, IpAddress, bin(TimeGenerated, 1h)
| where FileAccessCount > 100 or UniqueFiles > 50`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows EventCode=5145
| stats count dc(ObjectName) as unique_files values(ShareName) as shares by src_ip, user, _time span=1h
| where count > 100 OR unique_files > 50`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Network Share Access - T1039
id: f6a7b8c9-0123-45ef-0123-000000001039
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
    filter:
        ShareName|contains: '$'
    condition: selection and not filter
level: low
tags:
    - attack.collection
    - attack.t1039`
        }
      ]
    },
    // T1123 - Audio Capture
    {
      id: "T1123",
      name: "Audio Capture",
      description: "Detects audio capture activity that could be used for surveillance.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where ProcessCommandLine has_any ("mciSendString", "waveIn", "AudioCapture", "microphone", "recording")
    or FileName has_any ("soundrecorder.exe", "voicerecorder.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Audio Capture Activity - T1123
id: a7b8c9d0-1234-56f0-1234-000000001123
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith:
            - '\\soundrecorder.exe'
            - '\\voicerecorder.exe'
    selection_api:
        CommandLine|contains:
            - 'mciSendString'
            - 'waveIn'
            - 'AudioCapture'
    condition: selection_process or selection_api
level: medium
tags:
    - attack.collection
    - attack.t1123`
        }
      ]
    },
    // T1125 - Video Capture
    {
      id: "T1125",
      name: "Video Capture",
      description: "Detects video/webcam capture activity.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where ProcessCommandLine has_any ("VideoCaptureDevice", "webcam", "DirectShow", "MediaCapture", "camera")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Video Capture Activity - T1125
id: b8c9d0e1-2345-67a1-2345-000000001125
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'VideoCaptureDevice'
            - 'webcam'
            - 'MediaCapture'
            - 'DirectShow'
    condition: selection
level: medium
tags:
    - attack.collection
    - attack.t1125`
        }
      ]
    },
    // T1114.001 - Local Email Collection
    {
      id: "T1114.001",
      name: "Local Email Collection",
      description: "Detects access to local email files (PST, OST, EML).",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceFileEvents
| where FileName endswith ".pst" or FileName endswith ".ost" or FileName endswith ".eml"
| where ActionType in ("FileRead", "FileAccessed", "FileCopied")
| where InitiatingProcessFileName !in~ ("outlook.exe", "OUTLOOK.EXE")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=sysmon (EventCode=11 OR EventCode=23)
(TargetFilename="*.pst" OR TargetFilename="*.ost" OR TargetFilename="*.eml")
NOT Image="*\\OUTLOOK.EXE"
| stats count values(TargetFilename) as files by Computer, Image`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Local Email Collection - T1114.001
id: c9d0e1f2-3456-78b2-3456-000000114001
status: stable
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '.pst'
            - '.ost'
            - '.eml'
    filter:
        Image|endswith: '\\OUTLOOK.EXE'
    condition: selection and not filter
level: high
tags:
    - attack.collection
    - attack.t1114.001`
        }
      ]
    },
    // T1119 - Automated Collection
    {
      id: "T1119",
      name: "Automated Collection",
      description: "Detects automated data collection scripts and tools.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `DeviceProcessEvents
| where ProcessCommandLine has_any ("Get-ChildItem -Recurse", "dir /s", "forfiles", "robocopy")
| where ProcessCommandLine has_any (".doc", ".xls", ".pdf", ".txt", ".ppt", "Documents", "Desktop")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688)
(CommandLine="*Get-ChildItem*-Recurse*" OR CommandLine="*dir /s*" OR CommandLine="*robocopy*")
(CommandLine="*.doc*" OR CommandLine="*.xls*" OR CommandLine="*.pdf*" OR CommandLine="*Documents*")
| stats count by Computer, User, Image, CommandLine`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Automated Data Collection - T1119
id: d0e1f2a3-4567-89c3-4567-000000001119
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection_recursive:
        CommandLine|contains:
            - 'Get-ChildItem'
            - '-Recurse'
            - 'dir /s'
            - 'robocopy'
    selection_filetypes:
        CommandLine|contains:
            - '.doc'
            - '.xls'
            - '.pdf'
            - 'Documents'
    condition: selection_recursive and selection_filetypes
level: medium
tags:
    - attack.collection
    - attack.t1119`
        }
      ]
    }
  ],

  // ======================
  // TA0011 – Command and Control
  // ======================
  "TA0011": [
    {
      id: "T1071.002",
      name: "File Transfer Protocols C2",
      description: "Detects adversaries using FTP/SFTP for command and control or data exfiltration.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let ftp_ports = dynamic([20, 21, 22, 115, 989, 990]);
CommonSecurityLog
| where DestinationPort in (ftp_ports)
| summarize TotalBytes = sum(SentBytes + ReceivedBytes), ConnectionCount = count() by SourceIP, bin(TimeGenerated, 1h)
| where TotalBytes > 50000000 or ConnectionCount > 50`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=network (dest_port IN (20, 21, 22, 115, 989, 990) OR app IN ("ftp", "sftp", "scp"))
| stats sum(bytes) as total_bytes, count as connection_count by src_ip, _time span=1h
| where total_bytes > 50000000 OR connection_count > 50`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, destinationip, SUM(bytessent + bytesreceived) as total_bytes, COUNT(*) as connection_count
FROM events WHERE destinationport IN (20, 21, 22, 115, 989, 990)
GROUP BY sourceip, destinationip HAVING SUM(bytessent + bytesreceived) > 50000000
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `network where event.category == "network" and destination.port in (20, 21, 22, 115, 989, 990) and
network.bytes > 50000000`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Suspicious FTP/SFTP Activity - T1071.002
id: f7a8b9c0-1d2e-3f4a-5b6c-7d8e9f0a1b2c
status: experimental
logsource:
    category: firewall
detection:
    selection_ports:
        dst_port:
            - 20
            - 21
            - 22
            - 989
            - 990
    condition: selection_ports
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.002`
        }
      ]
    },
    {
      id: "T1071.003",
      name: "Mail Protocols C2",
      description: "Detects adversaries using email protocols (SMTP, IMAP, POP3) for command and control.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let mail_ports = dynamic([25, 110, 143, 465, 587, 993, 995]);
CommonSecurityLog
| where DestinationPort in (mail_ports)
| summarize TotalBytes = sum(SentBytes), ConnectionCount = count() by SourceIP, DestinationIP, bin(TimeGenerated, 1h)
| where TotalBytes > 10000000 or ConnectionCount > 100`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=network (dest_port IN (25, 110, 143, 465, 587, 993, 995) OR app IN ("smtp", "imap", "pop3"))
| stats sum(bytes_out) as total_bytes, count as connection_count by src_ip, _time span=1h
| where total_bytes > 10000000 OR connection_count > 100`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, destinationip, SUM(bytessent) as bytes_sent, COUNT(*) as connection_count
FROM events WHERE destinationport IN (25, 110, 143, 465, 587, 993, 995)
GROUP BY sourceip, destinationip HAVING SUM(bytessent) > 10000000
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `network where event.category == "network" and destination.port in (25, 110, 143, 465, 587, 993, 995) and
network.bytes > 10000000`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Suspicious Mail Protocol Activity - T1071.003
id: e8b9c0d1-2e3f-4a5b-6c7d-8e9f0a1b2c3d
status: experimental
logsource:
    category: firewall
detection:
    selection_ports:
        dst_port:
            - 25
            - 110
            - 143
            - 465
            - 587
            - 993
            - 995
    condition: selection_ports
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.003`
        }
      ]
    },
    {
      id: "T1105",
      name: "Ingress Tool Transfer",
      description: "Detects remote file downloads using certutil, bitsadmin, and PowerShell download cradles.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let downloadTools = dynamic(["certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe"]);
let psDownloadMethods = dynamic(["DownloadString", "DownloadFile", "Invoke-WebRequest", "IWR", "Net.WebClient", "Start-BitsTransfer"]);
DeviceProcessEvents
| where (FileName in~ (downloadTools) and ProcessCommandLine has_any ("http://", "https://", "-urlcache", "-split", "/transfer"))
    or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has_any (psDownloadMethods))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688)
((Image="*certutil.exe" AND (CommandLine="*-urlcache*" OR CommandLine="*http*"))
OR (Image="*bitsadmin.exe" AND CommandLine="*/transfer*")
OR (Image="*powershell.exe" AND (CommandLine="*DownloadString*" OR CommandLine="*DownloadFile*" OR CommandLine="*Invoke-WebRequest*")))
| stats count by Computer, User, Image, CommandLine`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, username, "Process Name" as proc, "Process CommandLine" as cmdline FROM events
WHERE ("Process Name" ILIKE '%certutil.exe' AND ("Process CommandLine" ILIKE '%-urlcache%' OR "Process CommandLine" ILIKE '%http%'))
OR ("Process Name" ILIKE '%bitsadmin.exe' AND "Process CommandLine" ILIKE '%/transfer%')
OR ("Process Name" ILIKE '%powershell.exe' AND ("Process CommandLine" ILIKE '%DownloadString%' OR "Process CommandLine" ILIKE '%Invoke-WebRequest%'))
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `process where event.type == "start" and
((process.name : "certutil.exe" and process.command_line : ("*-urlcache*", "*http*"))
or (process.name : "bitsadmin.exe" and process.command_line : "*/transfer*")
or (process.name : ("powershell.exe", "pwsh.exe") and process.command_line : ("*DownloadString*", "*DownloadFile*", "*Invoke-WebRequest*")))`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Ingress Tool Transfer - T1105
id: f5a6b7c8-d9e0-1234-5678-9abcdef01234
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_certutil:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains:
            - '-urlcache'
            - 'http://'
            - 'https://'
    selection_bitsadmin:
        Image|endswith: '\\bitsadmin.exe'
        CommandLine|contains: '/transfer'
    selection_powershell:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'Invoke-WebRequest'
    condition: selection_certutil or selection_bitsadmin or selection_powershell
level: high
tags:
    - attack.command_and_control
    - attack.t1105`
        }
      ]
    },
    {
      id: "T1132.001",
      name: "Data Encoding - Standard Encoding",
      description: "Detects Base64 encoded C2 traffic and encoded beacon data in process execution.",
      rules: [
        {
          type: "Sentinel KQL",
          lang: "sentinel",
          code: `let encodingIndicators = dynamic(["-EncodedCommand", "-enc ", "-ec ", "FromBase64String", "ToBase64String", "[Convert]::FromBase64"]);
DeviceProcessEvents
| where ProcessCommandLine has_any (encodingIndicators)
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "certutil.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`
        },
        {
          type: "Splunk SPL",
          lang: "splunk",
          code: `index=windows (EventCode=1 OR EventCode=4688)
(CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *" OR CommandLine="*FromBase64String*" OR CommandLine="*ToBase64String*")
OR (CommandLine="*certutil*" AND CommandLine="*-decode*")
| stats count by Computer, User, Image, CommandLine`
        },
        {
          type: "QRadar AQL",
          lang: "qradar",
          code: `SELECT sourceip, username, "Process CommandLine" as cmdline FROM events
WHERE ("Process CommandLine" ILIKE '%-EncodedCommand%'
OR "Process CommandLine" ILIKE '%-enc %'
OR "Process CommandLine" ILIKE '%FromBase64String%'
OR ("Process CommandLine" ILIKE '%certutil%' AND "Process CommandLine" ILIKE '%-decode%'))
LAST 24 HOURS`
        },
        {
          type: "Elastic EQL",
          lang: "elastic",
          code: `process where process.command_line : ("*-EncodedCommand*", "*-enc *", "*FromBase64String*", "*ToBase64String*")
or (process.name : "certutil.exe" and process.command_line : "*-decode*")`
        },
        {
          type: "Sigma",
          lang: "sigma",
          code: `title: Base64 Encoding Detection - T1132.001
id: b2c3d4e5-6789-0abc-def1-23456789abcd
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_encoded_cmd:
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
    selection_base64:
        CommandLine|contains:
            - 'FromBase64String'
            - 'ToBase64String'
    selection_certutil:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains: '-decode'
    condition: selection_encoded_cmd or selection_base64 or selection_certutil
level: medium
tags:
    - attack.command_and_control
    - attack.t1132.001`
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
const themeToggle = document.getElementById('theme-toggle');
const toastContainer = document.getElementById('toast-container');

// SIEM Icons with colored dots
const SIEM_COLORS = {
  splunk: 'splunk',
  sentinel: 'sentinel',
  kql: 'sentinel',
  qradar: 'qradar',
  elastic: 'elastic',
  sigma: 'sigma'
};

// Statistics
let totalTechniques = 0;
let totalRules = 0;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  if (matrixGrid) {
    calculateStats();
    renderMatrix();
    setupSearch();
    setupFilters();
    setupKeyboardShortcuts();
  }
  setupSidebarTabs();
  updateStatsDisplay();
});

// Theme Management
function initTheme() {
  const savedTheme = localStorage.getItem('detectionhub-theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

  if (savedTheme) {
    document.documentElement.setAttribute('data-theme', savedTheme);
  } else if (prefersDark) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }

  if (themeToggle) {
    themeToggle.addEventListener('click', toggleTheme);
  }
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('detectionhub-theme', next);
  showToast(`Switched to ${next} mode`, 'info');
}

// Statistics
function calculateStats() {
  totalTechniques = 0;
  totalRules = 0;

  Object.values(TECHNIQUES).forEach(techniques => {
    techniques.forEach(tech => {
      totalTechniques++;
      if (tech.rules && tech.rules.length > 0) {
        totalRules += tech.rules.length;
      }
    });
  });
}

function updateStatsDisplay() {
  const techEl = document.getElementById('total-techniques');
  const rulesEl = document.getElementById('total-rules');

  if (techEl) animateNumber(techEl, totalTechniques);
  if (rulesEl) animateNumber(rulesEl, totalRules);
}

function animateNumber(element, target) {
  const duration = 1000;
  const start = 0;
  const startTime = performance.now();

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.floor(start + (target - start) * eased);
    element.textContent = current.toLocaleString();

    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }

  requestAnimationFrame(update);
}

// Keyboard Shortcuts
function setupKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    // Ctrl+K or Cmd+K to focus search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      searchInput?.focus();
    }
    // Escape to close sidebar
    if (e.key === 'Escape') {
      closeSidebar();
    }
  });
}

// Toast Notifications
function showToast(message, type = 'info') {
  if (!toastContainer) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <svg class="icon" viewBox="0 0 24 24">
      ${type === 'success' ? '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>' :
        type === 'error' ? '<circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line>' :
        '<circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line>'}
    </svg>
    <span>${message}</span>
  `;

  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('toast-out');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// Copy to Clipboard
function copyToClipboard(text, button) {
  if (!text) {
    showToast('Nothing to copy', 'error');
    return;
  }

  navigator.clipboard.writeText(text).then(() => {
    const originalHTML = button.innerHTML;
    button.innerHTML = '<svg class="icon" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied!';
    button.classList.add('copied');
    showToast('Code copied to clipboard!', 'success');

    setTimeout(() => {
      button.innerHTML = originalHTML;
      button.classList.remove('copied');
    }, 2000);
  }).catch((err) => {
    // Fallback for older browsers
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      button.innerHTML = '<svg class="icon" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied!';
      button.classList.add('copied');
      showToast('Code copied to clipboard!', 'success');
      setTimeout(() => {
        button.innerHTML = '<svg class="icon" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copy';
        button.classList.remove('copied');
      }, 2000);
    } catch (e) {
      showToast('Failed to copy', 'error');
    }
    document.body.removeChild(textarea);
  });
}

// Filters
function setupFilters() {
  const filterPills = document.querySelectorAll('.filter-pill');

  filterPills.forEach(pill => {
    pill.addEventListener('click', () => {
      const filter = pill.dataset.filter;

      // Handle "all" filter
      if (filter === 'all') {
        filterPills.forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        showAllTechniques();
        return;
      }

      // Toggle SIEM filters
      if (pill.classList.contains('siem-filter')) {
        document.querySelector('.filter-pill[data-filter="all"]')?.classList.remove('active');
        pill.classList.toggle('active');
      } else {
        filterPills.forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
      }

      applyFilters();
    });
  });
}

function showAllTechniques() {
  document.querySelectorAll('.technique-card').forEach(card => {
    card.classList.remove('filtered');
    card.style.opacity = '1';
  });
}

function applyFilters() {
  const activeFilters = Array.from(document.querySelectorAll('.filter-pill.active'))
    .map(p => p.dataset.filter);

  document.querySelectorAll('.technique-card').forEach(card => {
    const siems = (card.dataset.siems || '').split(',');
    const hasRules = card.dataset.hasRules === 'true';

    let show = true;

    if (activeFilters.includes('with-rules') && !hasRules) {
      show = false;
    }

    const siemFilters = activeFilters.filter(f => ['sentinel', 'splunk', 'qradar', 'elastic', 'sigma'].includes(f));
    if (siemFilters.length > 0 && !siemFilters.some(f => siems.includes(f))) {
      show = false;
    }

    card.classList.toggle('filtered', !show);
    card.style.opacity = show ? '1' : '0.2';
  });
}

// --- MATRIX ---
function renderMatrix() {
  if (!matrixGrid) return;
  matrixGrid.innerHTML = '';

  // Map tactic names to CSS-friendly slugs
  const tacticSlugMap = {
    'TA0043': 'reconnaissance',
    'TA0042': 'resource-development',
    'TA0001': 'initial-access',
    'TA0002': 'execution',
    'TA0003': 'persistence',
    'TA0004': 'privilege-escalation',
    'TA0005': 'defense-evasion',
    'TA0006': 'credential-access',
    'TA0007': 'discovery',
    'TA0008': 'lateral-movement',
    'TA0009': 'collection',
    'TA0011': 'command-and-control',
    'TA0010': 'exfiltration',
    'TA0040': 'impact'
  };

  TACTICS.forEach(tactic => {
    const column = document.createElement('div');
    column.className = 'tactic-column';
    column.setAttribute('data-tactic', tacticSlugMap[tactic.id] || tactic.name.toLowerCase().replace(/\s+/g, '-'));

    const tacticsTechniques = TECHNIQUES[tactic.id] || [];
    const techniqueCount = tacticsTechniques.length;
    const rulesCount = tacticsTechniques.reduce((sum, t) => sum + (t.rules?.length || 0), 0);

    const header = document.createElement('div');
    header.className = 'tactic-header';
    header.innerHTML = `
      <div class="tactic-title">${tactic.name}</div>
      <div class="tactic-id">${tactic.id}</div>
      <div class="tactic-count">
        <span>${techniqueCount}</span> techniques
        ${rulesCount > 0 ? `<span class="text-success"> • ${rulesCount} rules</span>` : ''}
      </div>
    `;

    const list = document.createElement('div');
    list.className = 'technique-list';

    tacticsTechniques.forEach(tech => {
      const hasRules = tech.rules && tech.rules.length > 0;
      const siems = hasRules ? [...new Set(tech.rules.map(r => getSiemType(r.lang)))].filter(Boolean) : [];

      const card = document.createElement('div');
      card.className = `technique-card ${hasRules ? 'has-rules' : ''}`;
      card.setAttribute('data-has-rules', hasRules);
      card.setAttribute('data-siems', siems.join(','));
      card.setAttribute('data-tech-id', tech.id);
      card.onclick = () => openSidebar(tech, tactic);

      card.innerHTML = `
        <div class="tech-name">${tech.name}</div>
        <div class="tech-meta">
          <span class="tech-id">${tech.id}</span>
          ${hasRules ? `
            <div class="rule-indicators">
              ${siems.map(siem => `<div class="rule-indicator siem-dot ${siem}" title="${siem}"></div>`).join('')}
            </div>
          ` : ''}
        </div>
        ${tech.subtechniques?.length ? `<div class="sub-indicator"><span></span><span></span><span></span></div>` : ''}
      `;
      list.appendChild(card);
    });

    column.appendChild(header);
    column.appendChild(list);
    matrixGrid.appendChild(column);
  });
}

function getSiemType(lang) {
  if (!lang) return null;
  const l = lang.toLowerCase();
  if (l.includes('sentinel') || l.includes('kql')) return 'sentinel';
  if (l.includes('splunk') || l.includes('spl')) return 'splunk';
  if (l.includes('qradar') || l.includes('aql')) return 'qradar';
  if (l.includes('elastic') || l.includes('eql')) return 'elastic';
  if (l.includes('sigma')) return 'sigma';
  return null;
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

  let debounceTimer;
  searchInput.addEventListener('input', e => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      const query = e.target.value.toLowerCase().trim();

      document.querySelectorAll('.technique-card').forEach(card => {
        const name = card.querySelector('.tech-name')?.textContent.toLowerCase() || '';
        const id = card.dataset.techId?.toLowerCase() || '';
        const matches = !query || name.includes(query) || id.includes(query);

        card.classList.toggle('filtered', !matches);
        card.style.opacity = matches ? '1' : '0.15';
        card.style.transform = matches ? '' : 'scale(0.98)';
      });

      // Update tactic columns visibility
      document.querySelectorAll('.tactic-column').forEach(col => {
        const visibleCards = col.querySelectorAll('.technique-card:not(.filtered)').length;
        col.style.opacity = visibleCards > 0 ? '1' : '0.5';
      });
    }, 150);
  });

  // Clear search on Escape
  searchInput.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      searchInput.value = '';
      searchInput.dispatchEvent(new Event('input'));
      searchInput.blur();
    }
  });
}

// --- SIDEBAR ---
function openSidebar(tech, tactic = null) {
  if (!sidebar || !sidebarOverlay) return;

  const rulesCount = tech.rules?.length || 0;

  // Header info
  sidebar.querySelector('#sb-title').textContent = tech.name || '';
  sidebar.querySelector('#sb-id').textContent = tech.id || '';
  sidebar.querySelector('#sb-desc').textContent = tech.description || '';

  // Tactic badge
  const tacticBadge = sidebar.querySelector('#sb-tactic');
  if (tacticBadge && tactic) {
    tacticBadge.textContent = tactic.name;
    tacticBadge.style.display = 'inline-flex';
  } else if (tacticBadge) {
    tacticBadge.style.display = 'none';
  }

  // Rule count badge
  const ruleCountBadge = sidebar.querySelector('#sb-rule-count');
  if (ruleCountBadge) {
    ruleCountBadge.textContent = `${rulesCount} Rule${rulesCount !== 1 ? 's' : ''}`;
    ruleCountBadge.className = rulesCount > 0 ? 'badge success' : 'badge';
  }

  // Tab badge
  const rulesTabCount = sidebar.querySelector('#rules-tab-count');
  if (rulesTabCount) {
    rulesTabCount.textContent = rulesCount;
  }

  // MITRE Link
  const mitreLink = sidebar.querySelector('#sb-mitre-link');
  if (mitreLink && tech.id) {
    const baseId = tech.id.split('.')[0];
    const subId = tech.id.includes('.') ? tech.id.split('.')[1] : null;
    const url = subId
      ? `https://attack.mitre.org/techniques/${baseId}/${subId}/`
      : `https://attack.mitre.org/techniques/${tech.id}/`;
    mitreLink.href = url;
  }

  // Subtechniques
  const sub = sidebar.querySelector('#sb-subtechniques');
  if (sub) {
    sub.innerHTML = tech.subtechniques?.length
      ? tech.subtechniques.map(s => `
          <span class="badge" onclick="navigateToSubtechnique('${s}')" style="cursor:pointer;">
            ${s}
          </span>
        `).join('')
      : '<span class="text-muted">No subtechniques</span>';
  }

  // Details markdown
  const details = sidebar.querySelector('#sb-details');
  if (details) {
    if (tech.details?.detailsMarkdown) {
      details.innerHTML = renderMarkdown(tech.details.detailsMarkdown);
    } else {
      details.innerHTML = `
        <div class="empty-state" style="padding: var(--space-6);">
          <p class="text-muted">No additional analysis notes available.</p>
          <p class="text-muted text-sm" style="margin-top: var(--space-2);">
            Detection rules are available in the Rules tab.
          </p>
        </div>
      `;
    }
  }

  // Render rules
  renderRules(tech.rules || []);

  // Switch to details tab by default
  switchTab('details');

  // Show sidebar & overlay
  sidebar.classList.add('open');
  sidebarOverlay.classList.add('open');
  document.body.style.overflow = 'hidden';
}

function navigateToSubtechnique(subId) {
  // Find technique by ID
  for (const [tacticId, techniques] of Object.entries(TECHNIQUES)) {
    const tech = techniques.find(t => t.id === subId);
    if (tech) {
      const tactic = TACTICS.find(t => t.id === tacticId);
      openSidebar(tech, tactic);
      return;
    }
  }
  showToast(`Subtechnique ${subId} not found`, 'error');
}

function closeSidebar() {
  if (!sidebar || !sidebarOverlay) return;
  sidebar.classList.remove('open');
  sidebarOverlay.classList.remove('open');
  document.body.style.overflow = '';
}

function renderRules(rules) {
  const container = document.getElementById('sb-rules-list');
  if (!container) return;

  if (!rules.length) {
    container.innerHTML = `
      <div class="empty-state">
        <svg class="empty-state-icon icon-lg" viewBox="0 0 24 24">
          <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"></path>
        </svg>
        <h4 class="empty-state-title">No Detection Rules</h4>
        <p class="empty-state-desc">Detection rules for this technique are coming soon.</p>
      </div>
    `;
    return;
  }

  // Create rules HTML
  let html = '';
  rules.forEach((rule, index) => {
    const siemType = getSiemType(rule.lang);

    html += `
      <div class="code-block" data-siem="${siemType || 'default'}">
        <div class="code-header">
          <div class="code-lang">
            <span class="siem-dot ${siemType || ''}"></span>
            ${escapeHtml(rule.type || rule.lang)}
          </div>
          <button class="copy-btn" data-rule-index="${index}">
            <svg class="icon" viewBox="0 0 24 24">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
            Copy
          </button>
        </div>
        <div class="code-content">
          <pre></pre>
        </div>
      </div>
    `;
  });

  container.innerHTML = html;

  // Set code content using textContent to avoid HTML parsing issues
  const preElements = container.querySelectorAll('.code-content pre');
  rules.forEach((rule, index) => {
    if (preElements[index]) {
      preElements[index].textContent = rule.code;
    }
  });

  // Add copy button handlers
  const copyButtons = container.querySelectorAll('.copy-btn');
  copyButtons.forEach((btn, index) => {
    btn.addEventListener('click', () => {
      const code = rules[index]?.code || '';
      copyToClipboard(code, btn);
    });
  });
}

function escapeHtml(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// --- TABS ---
function setupSidebarTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', e => {
      const target = e.currentTarget;
      const tabName = target.dataset.tab;
      if (tabName) switchTab(tabName);
    });
  });
}

function switchTab(tabName) {
  if (!tabName) return;

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabName);
  });

  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.toggle('active', content.id === `tab-${tabName}`);
  });
}

// Expose globally
window.closeSidebar = closeSidebar;
window.switchTab = switchTab;
window.copyToClipboard = copyToClipboard;
window.navigateToSubtechnique = navigateToSubtechnique;

