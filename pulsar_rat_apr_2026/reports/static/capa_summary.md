# CAPA Analysis Summary - Pulsar RAT (RMnsgES.exe)

**SHA256**: `8f31c06c8e7ea9eb451bf26666ac4a958bb485b2a8b71feace1981633b116c92`
**Risk Score**: 100/100 (RED ALERT)
**Total Rules Matched**: 150
**Needs Investigation**: Yes

## ATT&CK Coverage

| Tactic | Technique | ID | Rules |
|---|---|---|---|
| Execution | Windows Management Instrumentation | T1047 | access WMI data in .NET |
| Privilege Escalation | Access Token Manipulation | T1134 | acquire debug privileges |
| Privilege Escalation | Process Injection | T1055 | allocate or change RWX memory |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 | decode data using Base64 in .NET |
| Defense Evasion | Obfuscated Files or Information | T1027 | encrypt data using DPAPI |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | disable system features via registry |
| Defense Evasion | Modify Registry | T1112 | delete/modify registry keys and values |
| Credential Access | Credentials from Password Stores | T1555 | steal browser cookies and credentials |
| Discovery | File and Directory Discovery | T1083 | enumerate files, check paths |
| Discovery | System Information Discovery | T1082 | get OS version, query env vars |
| Discovery | System Owner/User Discovery | T1033 | get session user name |
| Discovery | Process Discovery | T1057 | find process by PID, enumerate processes |
| Discovery | System Network Configuration Discovery | T1016 | get networking interfaces |
| Discovery | Query Registry | T1012 | query/enumerate registry keys and values |
| Collection | Screen Capture | T1113 | capture screenshot via GDI+ |
| Collection | Input Capture: Keylogging | T1056.001 | log keystrokes via application hook |
| Collection | Clipboard Data | T1115 | check clipboard data |
| Command and Control | Ingress Tool Transfer | T1105 | download and write files |
| Impact | File Deletion | T1070.004 | delete files for cleanup |

## Capability Breakdown

### Credential Access (Critical)
- Steal browser credentials (Chrome, Firefox, Opera, Brave)
- Decrypt Windows DPAPI credential stores
- Harvest saved passwords and cookies
- Browser profile cloning (`CloneBrowserProfileAsync`)

### Command & Control (14 capabilities)
- Create HTTP requests and TCP sockets
- Download URLs and transfer files
- Send/receive data over network
- MessagePack-serialized protocol over AES-256

### Collection (11 capabilities)
- Screenshot capture via GDI+/CreateCompatibleDC
- Keylogger via Windows application hooks (SetWindowsHookEx)
- Clipboard monitoring
- TCP connection and listener enumeration
- File system enumeration and search

### Evasion (15 capabilities)
- Debugger detection via API (IsDebuggerPresent)
- Sandbox username/hostname checking
- ProcessDebugFlags / ProcessDebugPort checks
- System feature disabling via registry
- Delayed execution for dynamic analysis evasion
- Base64 decode for obfuscated payloads

### Execution (13 capabilities)
- WMI data access for system management
- Debug privilege acquisition
- RWX memory allocation (process injection)
- Process creation with modified I/O handles
- Process memory minidump creation (credential dumping)

### Persistence (7 capabilities)
- Default file association registry hijacking
- Registry key/value manipulation
- UAC enable/disable (`DoEnableUAC`, `DoDisableUAC`)

### Reconnaissance (31 capabilities)
- Drive enumeration
- File/directory discovery and enumeration
- GUI resource enumeration
- OS version detection
- Network interface enumeration
- Process and service enumeration
- Environment variable querying
- Session user identification

## Embedded Dependencies (Fody/Costura)

The sample uses Fody/Costura to embed all .NET dependencies as compressed resources:

| DLL | Version | SHA1 |
|---|---|---|
| MessagePack.dll | 3.1.4.0 | B57B485BA7372FB3403FD0C36043A051AF2AFC05 |
| MessagePack.Annotations.dll | 3.1.4.0 | A0690708C86F009D41FDA400FEAD8407B8168895 |
| System.Buffers.dll | 4.0.3.0 | 2F410A0396BC148ED533AD49B6415FB58DD4D641 |
| System.Collections.Immutable.dll | 8.0.0.0 | 6E3CCF50BB1D30805DCE58AB6BDD63E0196669E6 |
| System.Memory.dll | 4.0.1.2 | 3C5C5DF5F8F8DB3F0A35C5ED8D357313A54E3CDE |
| System.Numerics.Vectors.dll | 4.1.4.0 | 3D216458740AD5CB05BC5F7C3491CDE44A1E5DF0 |
| System.Runtime.CompilerServices.Unsafe.dll | 6.0.3.0 | 43290CD4AAF80DF5D1CF9F242486EF8E646FDDDA |
| System.Threading.Tasks.Extensions.dll | 4.2.0.1 | 2242627282F9E07E37B274EA36FAC2D3CD9C9110 |
| Pulsar.Common.dll | 2.4.5.0 | 10B5E015B14D451DFAE1C36CCD9B6D96F1931127 |

## Key Namespaces Identified

```
Pulsar.Common.UAC              - UAC manipulation (DoEnableUAC, DoDisableUAC)
Pulsar.Common.Messages         - C2 message protocol
ClientManagement.UAC           - Client-side UAC bypass
```
