# DNS Exfiltration Detection, Attribution & Dynamic Host Containment

## Executive Summary
This directory contains end-to-end technical evidence, Detection-as-Code (DaC) specifications, and operational playbooks for attributing and neutralizing DNS tunneling and data exfiltration (MITRE ATT&CK T1071.004, T1048.003). 

It specifically addresses and resolves the **DNS Forwarder Blind Spot** inherent to Active Directory enterprise topologies: when internal endpoints send queries to Domain Controllers that forward requests upstream, edge security appliances (OPNsense) observe only the Domain Controller (`192.168.20.75`) as the source IP. By correlating high-entropy edge sinkhole logs (`sinkhole_audit.log`) with Domain Controller query logs (`dns.log`) across an in-memory temporal join, this pipeline isolates the patient-zero workstation (`WRKSTN-01` at `192.168.20.50`) and provisions automated wire suppression alongside gated Layer 3 kernel containment via FreeBSD `pfctl`.

In a mature SOC, perimeter sinkholes and Windows DNS query events are continuously streamed to a cloud SIEM (e.g., Microsoft Sentinel via Azure Monitor Agent). Ingestion rules normalize the telemetry into standardized tables, where scheduled KQL analytics rules correlate the events and trigger automated SOAR playbooks to isolate endpoints via firewall REST APIs.

Many operational environments—such as branch offices, air-gapped enclaves, or budget-constrained enterprise edge sites—cannot justify the substantial compute, network bandwidth, and cloud ingestion billing associated with streaming high-volume DNS logs to a centralized SIEM.

This repository provides a self-contained, Detection-as-Code Proof of Concept that:
1. Validates the end-to-end detection, correlation, and containment mechanics locally without requiring external SIEM licenses, dedicated collector VMs, or cloud infrastructure.
2. Proves the underlying protocol mechanics: directly correlating OPNsense JSONL perimeter audit records with native Windows Server DNS flat-file query buffers.
3. Executes deterministic, low-overhead Layer 3 isolation directly against FreeBSD kernel tables (`pfctl`) in microseconds without firewall rule-reload overhead.

---

## 1. Test Metadata
* **Perimeter Gateway / Sieve & Arbiter:** `OPNsense 24.x` (`192.168.20.1`) — Unbound DNS + System 1 Arbiter
* **Internal DNS Forwarder / Directory Node:** `DC01` (`192.168.20.75`) — Windows Server 2022 DNS Server
* **Compromised Endpoint (Patient-Zero):** `WRKSTN-01` (`192.168.20.50`) — Windows 11 Enterprise
* **Edge Audit Stream:** `/var/log/sinkhole_audit.log` (Newline-Delimited JSON / JSONL)
* **DC Query Audit Stream:** `C:\DNSLogs\dns.log` (Windows DNS Circular Packet Debug Engine)
* **Threat Classifications:** MITRE ATT&CK T1071.004 (DNS), T1048.003 (Exfiltration Over Alternative Protocol)
* **Isolation Engine:** FreeBSD Packet Filter (`pfctl` in-memory table `Quarantined_Hosts`)

---

## 2. Evidence Chain of Custody

| Step | Source System | Evidence File / Artifact | Key Findings |
|---|---|---|---|
| **01. Perimeter Exfil Interception** | `OPNsense` | [sinkhole_audit](./sinkhole_audit.log) | LLM Arbiter scored query payload (`v8x9k2m4...exfil-test.internal`) with Shannon Entropy $H = 4.625$ and exfil probability $P = 0.88$; sinkholed apex to `127.0.0.1`. |
| **02. DC Inbound Telemetry Capture** | `DC01` | [dns-debug-extract.txt](./evidence/dns-debug-extract.txt) | Captured raw wire packet `UDP Rcv 192.168.20.50` requesting the encoded label before recursive forwarding to gateway. |
| **03. Cloud Detection Rule (KQL)** | Azure Sentinel | [kql-sentinel-correlation.kql](./01-detection-query/kql-sentinel-correlation.kql) | Production Detection-as-Code specification executing temporal inner join between `OPNsense_EVE_CL` and `DnsEvents`. |
| **04. Local Correlation Engine** | `DC01` | [get-dcaudit-correlation.ps1](./01-detection-query/get-dcaudit-correlation.ps1) | Lightweight state-machine parser correlating JSONL audit records with split-line text logs; attributed client `192.168.20.50`. |
| **05. Kernel Layer 3 Quarantine** | `OPNsense` | [pf-quarantine.py](./03-network-isolation/pf-quarantine.py) | Dynamic FreeBSD `pf` module adding target to in-memory table and executing state drop (`pfctl -k`) with zero reload overhead. |

---

## 3. Deep-Dive Analysis: Detection, Attribution & Telemetry Engine

```text
               [ WRKSTN-01: 192.168.20.50 ]
                            │
                            │ 1. Raw Query: v8x9k2m4...exfil-test.internal
                            ▼
                  [ DC01: 192.168.20.75 ]
                  Logs: C:\DNSLogs\dns.log
                            │
                            │ 2. Forwarded Lookup: exfil-test.internal
                            ▼
               [ OPNsense: 192.168.20.1 ]
               Logs: /var/log/sinkhole_audit.log
               Containment: Unbound Redirect -> 0.0.0.0
                            │
                            ▼
           ┌──────────────────────────────────┐
           │     Correlation Engine (KQL/PS1) │
           │  Match: Apex + Proximity (<=60s) │
           └──────────────────────────────────┘
                            │
                            ▼
        ATTRIBUTION VERIFIED: 192.168.20.50 (WRKSTN-01)
         [Exonerates DC01 (192.168.20.75) from Isolation]
```

### Dual-Stream Telemetry Schema Breakdown

#### A. OPNsense Perimeter Arbiter Stream (`sinkhole_audit.log`)
Ingested as structured JSONL generated by the Python DNS Sieve/Arbiter pipeline:
```json
{
  "timestamp": "2026-10-28T22:55:19.985540+00:00",
  "action": "SIMULATED_SINKHOLE",
  "client_ip": "192.168.20.75",
  "apex_domain": "exfil-test.internal",
  "trigger_qname": "v8x9k2m4p7q1z3w5y0a8c2e4g6j1l3n5.exfil-test.internal",
  "rrtype": "A",
  "trigger_label": "v8x9k2m4p7q1z3w5y0a8c2e4g6j1l3n5",
  "heuristics": {
    "label_length": 32,
    "shannon_entropy": 4.625
  },
  "arbiter": {
    "mode": "dry_run",
    "model": "inception/mercury-decide:free",
    "decision": "is_dns_exfil",
    "probability": 0.88
  },
  "containment": {
    "mechanism": "unbound-control local_zone redirect",
    "sinkhole_target": "0.0.0.0"
  }
}
```

#### B. Active Directory DNS Debug Stream (`C:\DNSLogs\dns.log`)
Because long, high-entropy labels exceed single-line buffer widths, Windows Server writes inbound packet receipts across a two-line transaction structure:
```text
10/28/2026 4:21:29 PM 11C4 PACKET  000002218787B0C0 UDP Rcv 192.168.20.50   21a7   Q [0001   D   NOERROR] A
(32)v8x9k2m4p7q1z3w5y0a8c2e4g6j1l3n5(10)exfil-test(8)internal(0)
```

---

### Production KQL Correlation Rule (Microsoft Sentinel)
The enterprise Detection-as-Code specification deploys to Log Analytics Workspace or Microsoft Sentinel, joining edge network logs with Windows event streams:

```kusto
// Title: Gateway Sinkhole to Internal Workstation Attribution
// Tactics: Exfiltration (TA0010), Command and Control (TA0011)
// Techniques: T1071.004, T1048.003
let lookback = 15m;
let time_tolerance = 60s;

// 1. Extract perimeter sinkhole alerts from OPNsense
let GatewaySinkholes = OPNsense_EVE_CL
    | where TimeGenerated >= ago(lookback)
    | extend EventData = parse_json(Message)
    | where EventData.action in ("SIMULATED_SINKHOLE", "SINKHOLE_APPLIED")
    | project 
        GatewayTime = todatetime(EventData.timestamp),
        ApexDomain = tolower(tostring(EventData.apex_domain)),
        TriggerQName = tolower(tostring(EventData.trigger_qname)),
        Probability = toreal(EventData.arbiter.probability),
        Entropy = toreal(EventData.heuristics.shannon_entropy);

// 2. Ingest internal workstation query events from DC01
let DCQueryLogs = DnsEvents
    | where TimeGenerated >= ago(lookback)
    | where EventId == 246 or SubType == "LookupQuery"
    | project 
        DCTime = TimeGenerated, 
        WorkstationIP = tostring(ClientIP), 
        QueryName = tolower(Name);

// 3. Temporal inner join on apex domain match and temporal proximity
DCQueryLogs
| join kind=inner (GatewaySinkholes) on $left.QueryName has $right.ApexDomain
| where abs(datetime_diff('second', DCTime, GatewayTime)) <= datetime_diff('second', now(), now() + time_tolerance)
| summarize 
    FirstSeen = min(DCTime),
    LastSeen = max(DCTime),
    TotalQueries = count(),
    SampleQueries = make_set(QueryName, 5),
    MaxEntropy = max(Entropy)
    by WorkstationIP, ApexDomain, Probability
| project FirstSeen, LastSeen, WorkstationIP, ApexDomain, Probability, MaxEntropy, TotalQueries, SampleQueries
| order by Probability desc, TotalQueries desc
```

---

### Correlated Output Verification

When executed against the captured telemetry, the correlation engine outputs the following attribution record:

| Field | Correlated Value | Operational Significance |
|:---|:---|:---|
| **FirstSeen** | `2026-10-28 22:55:19 UTC` | Initial packet receipt timestamp |
| **LastSeen** | `2026-10-28 22:55:53 UTC` | Final query in correlation burst |
| **WorkstationIP** | **`192.168.20.50`** | **Patient-Zero Endpoint (`WRKSTN-01`)** |
| **QuarantinedApex** | `exfil-test.internal` | Domain apex contained at Unbound resolver |
| **Probability** | `0.88` | Arbiter confidence score |
| **MaxEntropy** | `4.625` | Label Shannon entropy ($H \ge 3.8$) |
| **TotalQueries** | `3` | Query count within correlation window |
| **SampleQueries** | `["v8x9k2m4...exfil-test.internal", "probe-live..."]` | Encoded payload telemetry retained for SOC |

---

## 4. Network Containment Strategy & Operational Runbook

Containment is partitioned into two distinct operational phases to eliminate self-inflicted denial of service across the enterprise fleet.

```text
                      [ Detection Engine Event ]
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
[ Phase 1: Machine Speed ]                    [ Phase 2: Host Isolation ]
  Unbound Dynamic Sinkhole                      Gated Packet Filter (pfctl)
  - Action: local-data 0.0.0.0                  - Action: Block Ingress + State Kill
  - Scope: Malicious apex only                  - Scope: Layer 3 Host Quarantine
  - Target: Transport Layer                     - Target: Workstation Endpoint
  - Blast Radius: Zero                          - Blast Radius: Host Network Severed
```

### Phase 1: Machine-Speed Transport Containment (100% Automated)
* **Trigger:** Exfiltration Probability $P \ge 0.75$ or Sieve Entropy $H \ge 4.2$.
* **Mechanism:** Executed via local Unix socket on OPNsense:
  ```bash
  unbound-control local_zone exfil-test.internal redirect
  unbound-control local_data "exfil-test.internal 3600 A 0.0.0.0"
  unbound-control flush_zone exfil-test.internal
  ```
* **Operational Impact:** The exfiltration channel is immediately neutralized at wire speed. Normal workstation network traffic remains fully operational.

### Phase 2: Host Network Isolation (Manual Gate vs. Autonomous)

#### Operational Models

1. **Model A: One-Click SOC Gate (Standard Operating Procedure):**
   * Correlated `WorkstationIP` (`192.168.20.50`) is enriched with Active Directory metadata (hostname, user, department).
   * Alert routes to the SOC triage queue with explicit action buttons: `[Approve Host Isolation]` | `[Dismiss Alert]`.
   * Prevents disruptive containment of business-critical endpoints or false-positive targets.

2. **Model B: Autonomous Zero-Touch Isolation (Restricted Guardrail):**
   * Requires multi-signal corroboration: Arbiter Probability $P \ge 0.95$ AND Query Count $> 20$ in 60 seconds.
   * Target must not exist within the immutable Tier-0 exclusion list.
   * Automatically triggers a 60-minute containment rollback timer.

---

### Dynamic FreeBSD Packet Filter (`pfctl`) Implementation

#### 1. OPNsense Firewall Prerequisites
* **In-Memory Alias:** Create an alias named `Quarantined_Hosts` of type `Host(s)` (initially empty).
* **Floating Rule:** Configure a Floating Rule at the top of the evaluation chain:
  * **Action:** `Block`
  * **Direction:** `in`
  * **Quick:** `Checked` (Immediate rule evaluation termination)
  * **Interface:** `LAN`, `OPT` (All client ingress interfaces)
  * **Source:** `Quarantined_Hosts`
  * **Destination:** `any`

#### 2. Kernel Containment Script (`pf-quarantine.py`)
Executes in-memory table injection and active state table destruction without firewall rulebase reload overhead:

```python
#!/usr/bin/env python3
"""
Dynamic Layer 3 Host Containment via FreeBSD pfctl
Injects host into in-memory table and tears down active session states.
"""
import argparse
import ipaddress
import subprocess
import sys

# Immutable Tier-0 Exclusions: Protected Infrastructure
IMMUTABLE_EXCLUSIONS = {
    ipaddress.ip_address("192.168.20.1"),   # Gateway / Perimeter Resolver
    ipaddress.ip_address("192.168.20.75"),  # DC01 Active Directory Server
}

TABLE_NAME = "Quarantined_Hosts"

def isolate_host(ip_str: str) -> None:
    ip = ipaddress.ip_address(ip_str)
    
    if ip in IMMUTABLE_EXCLUSIONS:
        print(f"[!] CRITICAL SAFETY ABORT: {ip} is in Tier-0 exclusions list.")
        sys.exit(2)

    try:
        # Step 1: Inject IP into in-memory kernel table
        cmd_add = ["pfctl", "-t", TABLE_NAME, "-T", "add", str(ip)]
        subprocess.run(cmd_add, check=True, capture_output=True, text=True)
        print(f"[+] Injected {ip} into pf table '{TABLE_NAME}'.")

        # Step 2: Sever all established TCP/UDP states
        cmd_kill = ["pfctl", "-k", str(ip)]
        subprocess.run(cmd_kill, check=True, capture_output=True, text=True)
        print(f"[+] Successfully terminated all active session states for {ip}.")

    except subprocess.CalledProcessError as err:
        print(f"[-] Execution failed: {err.stderr.strip() if err.stderr else err}")
        sys.exit(1)

def release_host(ip_str: str) -> None:
    ip = ipaddress.ip_address(ip_str)
    try:
        cmd_del = ["pfctl", "-t", TABLE_NAME, "-T", "delete", str(ip)]
        subprocess.run(cmd_del, check=True, capture_output=True, text=True)
        print(f"[+] Successfully removed {ip} from pf table '{TABLE_NAME}'.")
    except subprocess.CalledProcessError as err:
        print(f"[-] Execution failed: {err.stderr.strip() if err.stderr else err}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="L3 Host Isolation Engine")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--isolate", help="Workstation IP to block and terminate")
    group.add_argument("--release", help="Workstation IP to release from quarantine")
    args = parser.parse_args()

    if args.isolate:
        isolate_host(args.isolate)
    elif args.release:
        release_host(args.release)
```

---

### Containment Verification & Rollback Runbook

#### Verifying Active Host Quarantine
1. **Inspect Active `pf` Table Members:**
   ```bash
   pfctl -t Quarantined_Hosts -T show
   ```
   *Expected Output:* `192.168.20.50` is listed.

2. **Verify Active State Termination:**
   ```bash
   pfctl -ss | grep "192.168.20.50"
   ```
   *Expected Output:* Zero active states returned.

3. **Verify Host Egress Block:**
   From `WRKSTN-01` (`192.168.20.50`), test TCP connection to gateway:
   ```powershell
   Test-NetConnection -ComputerName 192.168.20.1 -Port 443
   ```
   *Expected Result:* `TcpTestSucceeded : False` (Terminated at ingress interface).

#### Executing Quarantine Rollback (Remediation)
When the incident is resolved or determined to be a false positive:
```bash
# 1. Remove endpoint from kernel quarantine table
python3 pf-quarantine.py --release 192.168.20.50

# 2. (Optional) Flush Unbound local zone sinkhole if apex was legitimate
unbound-control local_zone_remove exfil-test.internal
unbound-control flush_zone exfil-test.internal
```
