# Active Directory LDAPS Enumeration & Defense Efficacy Validation

## Executive Summary
This directory contains end-to-end evidence validating the detection and forensic analysis of automated Active Directory graph enumeration over encrypted transport (LDAPS, TCP 636) targeting primary domain controller `DC01`. It evaluates the detection boundary between network behavioral sensors (Suricata NIDS) and host-level directory diagnostic auditing (Windows NTDS Event ID 1644), documenting the cryptographic blinding of network inspection, stateful sensor engine failures, and the operational procedure for endpoint telemetry collection.

---

## 1. Test Metadata
* **Target Domain Controller:** `DC01.hybrid.lan` (`192.168.20.75`)
* **Attacker Host:** `kali` (`192.168.10.83`)
* **Target Directory Port:** TCP 636 (LDAP over TLS/SSL)
* **Compromised Account Context:** `hybrid.lan\asrep_user`
* **Network Sensor Platform:** OPNsense / Suricata
* **Monitored Transit Interface:** `em1`
* **Attack Tooling:** NetExec v1.x (`--bloodhound --collection All`)

---

## 2. Evidence Chain of Custody

| Step | Source System | Evidence File / Artifact | Key Findings |
|---|---|---|---|
| **01. Attack Execution & Ingest** | `kali` (Attacker) | [netexec-enumeration.log](./netexec-enumeration.log) | Executed NetExec enumeration via LDAPS; validated successful authentication as `asrep_user` and dumped 178 KB compressed BloodHound archive `DC01_192.168.20.75_2026-09-10_223152_bloodhound.zip`. |
| **02. Transit Boundary Wire Telemetry** | `em1` (OPNsense) | [tcpdump-ldaps-burst.pcap](./tcpdump-ldaps-burst.pcap) | Captured raw frame flow across ephemeral socket `37023 -> 636`; confirmed bidirectional TCP handshake, TLS negotiation, and line-rate saturation of consecutive 1448-byte payload segments. |
| **03. Network Sensor Detection** | Suricata (NIDS) | [eve-alert-1000099.json](./eve-alert-1000099.json) | Triggered Layer-4 signature `sid:1000099` (`LDAPS EGRESS HIT`); confirmed packet match on outbound DC response without relying on corrupted flow timers. |
| **04. Host Diagnostic Telemetry** | `DC01` (Active Directory) | [events.txt](./events.txt) | Captured Directory Service Event ID 1644 entries; exposed exact LDAP search filters, target attributes (`nTSecurityDescriptor`, `member`, `adminCount`), and calling client socket `192.168.10.83:37023`. |

---

## 3. Deep-Dive Analysis: Network vs. Host Telemetry Pipeline

### Network Boundary Telemetry & DPI Blinding
Because NetExec operates over an established TLS session on TCP port 636, Deep Packet Inspection (DPI) engines cannot inspect the ASN.1/BER LDAP structures on the wire:
* **Stateless Packet Signatures:** Suricata matches on raw Layer-4 transport metadata (`src_port 636 -> dest_port 37023`) as data streams out from the Domain Controller.
* **Payload Characteristics:** Packet telemetry shows saturated TCP data segments (`length 1448`), reflecting rapid object transfer rather than single authentication handshakes.

### Raw Packet Flow Telemetry (`em1`)
```text
# 1. TCP Three-Way Handshake
22:31:52.671566 IP 192.168.10.83.37023 > 192.168.20.75.636: Flags [S], seq 3161107261, win 64240, options [mss 1460,sackOK,TS val 676401108 ecr 0,nop,wscale 8], length 0
22:31:52.672242 IP 192.168.20.75.636 > 192.168.10.83.37023: Flags [S.], seq 3849368123, ack 3161107262, win 65535, options [mss 1460,nop,wscale 8,sackOK,TS val 18838884 ecr 676401108], length 0
22:31:52.672540 IP 192.168.10.83.37023 > 192.168.20.75.636: Flags [.], ack 1, win 251, options [nop,nop,TS val 676401109 ecr 18838884], length 0

# 2. TLS Session Establishment & Encrypted Search Query
22:31:52.673891 IP 192.168.10.83.37023 > 192.168.20.75.636: Flags [P.], seq 1:518, ack 1, win 251, options [nop,nop,TS val 676401110 ecr 18838884], length 517
22:31:52.675102 IP 192.168.20.75.636 > 192.168.10.83.37023: Flags [P.], seq 1:2543, ack 518, win 255, options [nop,nop,TS val 18838887 ecr 676401110], length 2542
22:31:52.697410 IP 192.168.10.83.37023 > 192.168.20.75.636: Flags [P.], seq 518:2801, ack 2543, win 251, options [nop,nop,TS val 676401131 ecr 18838887], length 2283

# 3. High-Rate LDAPS Object Tree Streaming (Saturated 1448-byte Segments)
22:31:52.698597 IP 192.168.20.75.636 > 192.168.10.83.37023: Flags [.], seq 5734:7182, ack 2801, win 251, options [nop,nop,TS val 18838911 ecr 676401131], length 1448
22:31:52.698618 IP 192.168.20.75.636 > 192.168.10.83.37023: Flags [.], seq 7182:8630, ack 2801, win 251, options [nop,nop,TS val 18838911 ecr 676401131], length 1448
22:31:52.698630 IP 192.168.20.75.636 > 192.168.10.83.37023: Flags [.], seq 8630:10078, ack 2801, win 251, options [nop,nop,TS val 18838911 ecr 676401131], length 1448
22:31:52.698641 IP 192.168.20.75.636 > 192.168.10.83.37023: Flags [.], seq 10078:11526, ack 2801, win 251, options [nop,nop,TS val 18838911 ecr 676401131], length 1448
22:31:52.698652 IP 192.168.20.75.636 > 192.168.10.83.37023: Flags [.], seq 11526:12974, ack 2801, win 251, options [nop,nop,TS val 18838911 ecr 676401131], length 1448
22:31:52.698663 IP 192.168.20.75.636 > 192.168.10.83.37023: Flags [.], seq 12974:14422, ack 2801, win 251, options [nop,nop,TS val 18838911 ecr 676401131], length 1448

# 4. Stream Tail / Final Flush
22:31:53.277016 IP 192.168.20.75.636 > 192.168.10.83.37023: Flags [.], seq 1079555:1081003, ack 18461, win 253, options [nop,nop,TS val 18839490 ecr 676401714], length 1448
22:31:53.277043 IP 192.168.20.75.636 > 192.168.10.83.37023: Flags [P.], seq 1081003:1082175, ack 18461, win 253, options [nop,nop,TS val 18839490 ecr 676401714], length 1172
```

### Suricata Sensor Alert (`eve.json`)
```json
{
  "timestamp": "2026-09-10T22:31:52.698597+0000",
  "flow_id": 1272562938529864,
  "in_iface": "em1",
  "event_type": "alert",
  "src_ip": "192.168.20.75",
  "src_port": 636,
  "dest_ip": "192.168.10.83",
  "dest_port": 37023,
  "proto": "TCP",
  "ip_v": 4,
  "pkt_src": "wire/pcap",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 1000099,
    "rev": 1,
    "signature": "LDAPS EGRESS HIT",
    "category": "",
    "severity": 3
  }
}
```

### Host-Side NTDS Telemetry (Event ID 1644)
Because network encryption masks query details, host-side NTDS diagnostics supply essential attribution and filter visibility:
* **Group & DACL Enumeration:** Evaluates `(objectClass=group)` while extracting binary security descriptors (`nTSecurityDescriptor`) and group memberships (`member`) to construct privilege escalation attack paths.
* **System Containers & OU Discovery:** Traverses the tree matching `(objectClass=container)` to locate critical system targets and group policy inheritance points.
* **Schema Resolution:** Queries `CN=Schema,CN=Configuration,DC=hybrid,DC=lan` to map schema GUIDs back to human-readable names for rights parsing.

```text
TimeCreated : 9/10/2026 10:31:52 PM
Message     : Internal event: A client issued a search operation with the following options. 
               
              Client:
              192.168.10.83:37023 
              Starting node:
              DC=hybrid,DC=lan 
              Filter:
               (objectClass=group)  
              Search scope:
              subtree 
              Attribute selection:
              distinguishedName,sAMAccountName,sAMAccountType,objectSid,member,adminCount,description,whenCreated,nTSecurityDescriptor 
              Server controls:
              SDflags:0x5; 
              Visited entries:
              53 
              Returned entries:
              52 
              Used indexes:
              idx_objectClass:53:N; 
              Search time (ms):
              0 
              User:
              HYBRID\asrep_user
```


---

## 4. Operational Considerations & Diagnostic Baseline Runbook

### Sensor Flow Lifecycle Limitations
When clients execute high-speed sweeps followed by connection resets (`Flags [R.]`), Suricata's flow management engine drops state tables before rate counters complete, frequently producing `APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION` diagnostics. Stateful in-rule filters (`threshold`, `detection_filter`) fail to increment across these short-lived flows, necessitating stateless payload inspections or external rate-limiting configurations (`threshold.config`).

### Diagnostic Configuration Protocol
Windows Domain Controllers run with NTDS query logging disabled by default. Use the following PowerShell runbook to configure diagnostic collection during an assessment and safely revert the system afterward:

1. **Enable NTDS Verbose Diagnostic Logging:**
   ```powershell
   # Elevate Field Engineering diagnostics to Level 5
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -Name "15 Field Engineering" -Value 5

   # Set query logging thresholds for expensive/inefficient searches (50 objects)
   New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "Expensive Search Results Threshold" -Value 50 -PropertyType DWORD -Force
   New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "Inefficient Search Results Threshold" -Value 50 -PropertyType DWORD -Force
   ```

2. **Restore Baseline Logging Configuration:**
   ```powershell
   # Reset Field Engineering logging back to disabled (0)
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -Name "15 Field Engineering" -Value 0

   # Remove custom threshold entries to prevent log flooding and disk overhead
   Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "Expensive Search Results Threshold" -ErrorAction SilentlyContinue
   Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "Inefficient Search Results Threshold" -ErrorAction SilentlyContinue
   ```
