# Active Directory Kerberos Threat Validation: AS-REP Roasting & NIDS Detection Pipeline

## Executive Summary
This directory contains end-to-end evidence validating internal Active Directory threat detection and network intrusion telemetry across routed virtualized infrastructure. It demonstrates how an unauthenticated attacker on an isolated segment (`192.168.10.0/24`) identifies accounts lacking Kerberos pre-authentication, extracts an encrypted Ticket Granting Ticket (TGT) hash, and generates correlated network alerts within an inline OPNsense Suricata NIDS engine as well as endpoint security audit events on the Domain Controller (`DC01`).

---

## 1. Test Metadata
* **Target Domain / Realm:** `hybrid.lan` (`HYBRID.LAN`)
* **Primary Domain Controller:** `DC01` (192.168.20.76) — Windows Server Active Directory / KDC
* **Attack Host:** Kali Linux (192.168.10.84) — Internal LAN segment (`em1`)
* **Network Sensor / Firewall:** OPNsense NIDS (Suricata engine bound to `em1` and `em3`)
* **Target Account:** `asrep_user@hybrid.lan` (`DONT_REQ_PREAUTH` enabled)
* **Attack Tooling:** Impacket v0.14.0.dev0 (`GetNPUsers`)
* **Detection Signatures:** Emerging Threats Open (Suricata) / Windows Security Audit Log

---

## 2. Evidence Chain of Custody

| Step | Source System | Evidence File / Artifact | Key Findings |
|---|---|---|---|
| **01. Vulnerable Directory State** | `DC01` | [preauth](./preauth.txt) | Executed Active Directory query; verified `DoesNotRequirePreAuth = True` and `userAccountControl = 4194816` (`0x400200`), validating pre-authentication bypass is enabled. |
| **02. Unauthenticated TGT Harvesting** | Kali Linux | [as-rep-result](./as-rep-result.jpg) | Executed `impacket-GetNPUsers` against `hybrid.lan`; extracted valid Kerberos 5 AS-REP ticket blob (`etype 23` RC4-HMAC) for offline dictionary recovery with cracking tooling. |
| **03. Host Security Audit Ingestion** | `DC01` | [DC01-as-rep-event](./DC01-as-rep-event.txt) | Verified Windows Event ID `4768` logged on `DC01`; recorded ticket request from `::ffff:192.168.10.84` with `Pre-Authentication Type: 0` (no pre-auth) and `Ticket Encryption Type: 0x17`. |
| **04. Network Threat Detection (NIDS)** | OPNsense | [asrep_evidence](./asrep_evidence.json) | Captured real-time alert in `eve.json`; Suricata flagged traffic with `SID 2019922` (`ET EXPLOIT Possible GoldenPac Priv Esc in-use`) on transit port `88/tcp` without NAT masking. |

---

## 3. Deep-Dive Analysis: Threat Architecture & Detection Correlation

### Attack Mechanics
Under RFC 4120, standard Kerberos authentication requires the client to encrypt a current timestamp using the user's password hash (`PA-ENC-TIMESTAMP`) in the initial `AS-REQ`. When the `DONT_REQ_PREAUTH` UserAccountControl attribute (`0x400000`) is assigned:
1. **Request Without Secret:** The attacker submits an unauthenticated `AS-REQ` referencing the target account.
2. **KDC Response:** The KDC returns an `AS-REP` containing the TGT and an encrypted session key blob keyed against the target account's password hash.
3. **Offline Recovery:** The returned `$krb5asrep$23$...` hash structure allows an adversary to perform high-speed offline dictionary or brute-force recovery using dedicated cracking utilities without triggering domain account lockout thresholds.

### Dual-Layer Telemetry Correlation
Detection is verified simultaneously across host and network layers:
* **Endpoint Telemetry (`Event ID 4768`):** The Domain Controller Security Event Log records a TGT request where `Pre-Authentication Type` explicitly logs as `0` instead of standard Kerberos pre-auth (`15` or `19`), directly attributable to client IP `192.168.10.84`.
* **Network NIDS Telemetry (`asrep_evidence.json`):** Suricata intercepts the TCP session across the internal transit bridge (`em1` to `em3`), decoding the Kerberos payload and raising an ET Open high-severity alert (`Category: Attempted Administrator Privilege Gain`) based on anomalous unauthenticated Kerberos formatting.

---

## 4. Remediation & Hardening Protocol

### 1. Audit Pre-Authentication Status
Audit domain accounts to identify any users operating with pre-authentication bypassed:

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth, userAccountControl | Select-Object SamAccountName, DoesNotRequirePreAuth, userAccountControl
```

### 2. Enforce Kerberos Pre-Authentication
Strip the `DONT_REQ_PREAUTH` bit from non-essential accounts:

```powershell
Set-ADAccountControl -Identity "asrep_user" -DoesNotRequirePreAuth $false
```

### 3. Credential Hygiene
Where legacy operational constraints strictly require `DONT_REQ_PREAUTH`, enforce 25+ character complex passphrases or migrate the workload to Group Managed Service Accounts (gMSA) to render offline dictionary attacks computationally infeasible.
