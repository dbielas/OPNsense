# OPNsense Real-Time DNS Exfiltration Detection & Automated Containment Pipeline

## Executive Summary
This directory contains end-to-end evidence validating the deployment, signal heuristics, and automated containment mechanics of an in-memory DNS exfiltration detection and mitigation pipeline on OPNsense. The system intercepts Suricata v3 EVE DNS telemetry directly from a volatile RAM disk (`tmpfs`), executes two-stage entropy and length gating across `A`, `AAAA`, and `TXT` queries in Python, invokes LLM probability arbitration via OpenRouter, and dynamically sinkholes malicious apex domains via Unbound DNS local zone redirects.

---

## 1. Test Metadata
* **Edge Firewall Node:** OPNsense Appliance (`opnsense.internal`)
* **Inspection Interface:** Internal Gateway (`192.168.20.1`)
* **Telemetry Source:** Suricata EVE DNS Engine (`/tmp/ramdisk/eve-dns.json`)
* **RAM Disk Backing:** 64MB `tmpfs` mounted at `/tmp/ramdisk`
* **Mitigation Daemon:** Unbound DNS Resolver (`/var/unbound/unbound.conf`)
* **Local Control Interface:** UNIX Domain Socket (`/var/run/unbound.ctl`) / CLI (`unbound-control`)
* **Arbitration Model:** `inception/mercury-decide:free` via OpenRouter Decision API
* **Decision Threshold:** P(Exfil) >= 0.75
* **Containment Target:** `127.0.0.1` (`local_zone redirect`)

---

## 2. Evidence Chain of Custody

| Step | Source System | Evidence File / Artifact | Key Findings |
|---|---|---|---|
| **01. Volatile RAM Disk Mount** | FreeBSD / OPNsense | [mount-ramdisk-status](./mount-ramdisk-status.txt) | Executed `mount -t tmpfs`; confirmed 64MB volatile storage mounted at `/tmp/ramdisk` with zero persistent flash writes. |
| **02. Suricata Telemetry Tap** | Suricata Engine | [suricata-eve-dns-sample](./suricata-eve-dns-sample.json) | Captured raw Suricata v3 EVE DNS queries; confirmed request-only logging to `/tmp/ramdisk/eve-dns.json` without response overhead. |
| **03. Benign Query Filtering** | Python Sieve | [sieve-benign-traffic](./sieve-benign-traffic.txt) | Evaluated normal queries (`_dmarc`, compound hostnames with >= 2 hyphens); confirmed immediate bypass without Arbiter queuing. |
| **04. Standard A/AAAA Flagging** | Python Sieve | [sieve-anomaly-standard](./sieve-anomaly-standard.txt) | Caught 27-char payload `Q09ORklERU5USUFMX1BBWVJPTEw` at H = 4.357; satisfied standard gates (Len >= 20, H >= 4.15). |
| **05. TXT Tunneling Flagging** | Python Sieve | [sieve-anomaly-txt](./sieve-anomaly-txt.txt) | Caught 32-char payload at H = 4.289 on `TXT` record; satisfied relaxed tunneling gates (Len >= 16, H >= 3.80). |
| **06. Apex Debounce Suppression** | Python Sieve | [sieve-debounce-burst](./sieve-debounce-burst.txt) | Ingested secondary query burst for `intruder.internal`; confirmed in-flight suppression within 30-second TTL window. |
| **07. OpenRouter Model Verdict** | Python Arbiter | [arbiter-decision-response](./arbiter-decision-response.txt) | Dispatched context payload to `inception/mercury-decide:free`; returned P(Exfil) = 0.9890 in 348.3ms. |
| **08. Unbound Socket Mitigation** | Python Arbiter | [unbound-containment-exec](./unbound-containment-exec.txt) | Executed `local_zone redirect` and `local_data A 127.0.0.1` via Arbiter. |
| **09. Unbound Zone Table State** | Unbound Resolver | [unbound-table-inspection](./unbound-table-inspection.txt) | Executed `unbound-control list_local_data \| grep 127.0.0.1`; confirmed volatile redirect entry for target apex. |
| **10. Client Containment Test** | `WRKSTN-01` | [client-resolution-verify](./client-resolution-verify.txt) | Resolved `test.intruder.internal` returning `127.0.0.1`, while benign internet lookups resolved cleanly. |
| **11. Forensic Audit Trail** | Edge Filesystem | [sinkhole-audit](./sinkhole-audit.json) | Validated JSON forensic record committed to `/var/log/sinkhole_audit.log` with timestamp, client IP, heuristics, and model confidence. |

---

## 3. Deep-Dive Analysis: Pipeline Architecture & Arbitration Logic

### Active Directory DNS Integration & Flow Topology

In this deployment, LAN firewall rules enforce centralized enterprise DNS architecture: internal workstations are permitted to query only the Active Directory Domain Controller, and direct outbound UDP/TCP port 53 to WAN is blocked.

```text
Production Resolution Architecture:
[Workstation: 192.168.20.50]
         │ (LAN Rule: Port 53 Allowed)
         ▼
[AD Domain Controller / DNS] ──── Authoritative for Internal Forest & SRV
         │
         │ (DNS Forwarder: Non-Authoritative / External)
         ▼
[OPNsense Gateway: 192.168.20.1]
   ├── Suricata v3 EVE DNS Tap (/tmp/ramdisk/eve-dns.json)
   ├── Sieve (Process 1) & Arbiter (Process 2)
   └── Unbound Resolver (Sinkhole Target: 127.0.0.1)
```

#### Containment Propagation

When the Arbiter executes dynamic containment via `unbound-control local_zone <apex> redirect`, Unbound begins answering external queries for that root domain with `127.0.0.1`. The AD DNS forwarder receives this poisoned record and caches it, propagating the sinkhole to all domain-joined endpoints querying the DC.

### Multi-Process Pipeline Topology
The pipeline runs two decoupled worker processes communicating over an in-memory queue (`multiprocessing.Queue`) to maintain wire-speed processing:
* **The Sieve (Process 1):** Attaches to the active EVE JSON stream in `/tmp/ramdisk/eve-dns.json`. Calculates Shannon entropy $H(X)$, evaluates label length, strips RFC metadata prefixes (`_dmarc`, `_domainkey`), drops hyphenated cloud infrastructure hostnames, and runs an LRU debounce cache to suppress burst queries.
* **The Arbiter (Process 2):** Consumes flagged candidate frames. Compiles query telemetry, sends structured decision payloads to OpenRouter (`inception/mercury-decide:free`), parses single-value confidence probabilities **P(Exfil) >= 0.75**, and executes dynamic sinkholing commands via `unbound-control`.

### Telemetry Source Rationale: Suricata EVE vs. Unbound dnstap

While `dnstap` provides native, high-performance query logging directly from resolver software, Suricata v3 EVE DNS streaming was chosen for the telemetry tap based on three architectural requirements:

* **OPNsense Package Portability:** The base FreeBSD Unbound package and OPNsense GUI template engine do not include `libfstrm` or `libprotobuf-c` compilation flags by default. Utilizing Suricata avoids custom binary rebuilds, maintaining complete compatibility with standard OPNsense firmware updates.
* **Wire-Level Visibility vs. Daemon Scoping:** `dnstap` captures only transactions that successfully reach the Unbound daemon socket. Suricata inspects raw frames at Layer 3/4 on the interface, providing packet-layer visibility over all outbound port 53 traffic—including any rogue or hardcoded client DNS lookups attempting to bypass the local resolver.
* **Zero-Dependency In-Memory Ingestion:** `dnstap` emits binary Frame Streams requiring protobuf deserialization in the consumer process. Suricata streams newline-delimited JSON directly to volatile memory (`/tmp/ramdisk/eve-dns.json`), allowing the Sieve to tail and decode records without external C-extensions, sockets, or binary protocol parsing overhead.
* **Resolver Performance Decoupling:** Logging remains strictly passive and decoupled from the Unbound process tree, preventing IPC socket backpressure or buffer exhaustion from impacting production resolver latency.

### Dual-Path Detection Heuristics
Because attacker tradecraft differs between high-volume IP address lookups and data-dense tunneling protocols (`dnscat2`, `iodine`), the Sieve implements differentiated gating logic:

| Query Record Type | Min Label Length | Min Shannon Entropy | Excluded Patterns |
|---|---|---|---|
| **Standard** (`A`, `AAAA`) | >= 20 characters | >= 4.15 bits/char | >= 2 hyphens, RFC underscore prefixes |
| **Tunneling** (`TXT`) | >= 16 characters | >= 3.80 bits/char | >= 2 hyphens, `_dmarc`, `_domainkey`, `acme-challenge` |

**Shannon Entropy:**: 
```math
H \(= -\sum P(x) \log_2\) P(x)
```
### Semantic Arbitration (LLM vs. Static Entropy)
Static threshold gates flag all high-entropy strings uniformly, causing false positives on base64 test strings. The LLM evaluates semantic byte structure:
* **Plaintext ASCII in Base64 (`VGhpcyBpcy...`):** $H = 4.289$, length 32. Model decodes "This is a test exfil txt", recognizes human test grammar, and outputs $P = 0.4073$ (below 0.75 threshold; bypasses sinkhole).
* **Encrypted Binary Payload:** $H = 4.562$, length 32. Model identifies unstructured, pseudorandom byte streams targeting an unauthorized apex and outputs $P = 0.9890$ (containment applied).

### Dynamic Containment Sequence
When the model returns **P(Exfil) >= 0.75**, the Arbiter injects containment rules directly into Unbound's running in-memory tree:
```bash
# 1. Create a wildcard redirection zone for the target apex
unbound-control -c /var/unbound/unbound.conf local_zone intruder.internal redirect

# 2. Sinkhole all lookups (*.intruder.internal) to localhost
unbound-control -c /var/unbound/unbound.conf local_data "intruder.internal A 127.0.0.1"

```
## 4. Test Harness & Reproduction Commands

### Benign Baseline Verification

```powershell
Resolve-DnsName -Name "_dmarc.intruder.internal" -Type TXT
```

### Burst Debounce Test (5 rapid queries)

```powershell
1..5 | ForEach-Object {
    $bytes = [byte[]](1..24 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 })
    $b64 = [Convert]::ToBase64String($bytes).Replace('+', 'A').Replace('/', 'B').Replace('=', '')
    Resolve-DnsName -Name "$b64.intruder.internal" -ErrorAction SilentlyContinue
}

```

### Semantic vs. Malicious Payload Test

```powershell
# Plaintext ASCII Base64 (Semantic pass - No sinkhole):
Resolve-DnsName -Name "VGhpcyBpcyBhIHRlc3QgZXhmaWwgdHh0.intruder.internal" -Type TXT

# Raw Binary Ciphertext (Malicious - Triggers 127.0.0.1 sinkhole):
$bytes = [byte[]](1..24 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 })
$b64 = [Convert]::ToBase64String($bytes).Replace('+', 'A').Replace('/', 'B').Replace('=', '')
Resolve-DnsName -Name "$b64.intruder.internal" -Type TXT

```
---

## 5. Operational Considerations & System Recovery Runbook

### Service Daemonization (`rc.d`)

To run the pipeline as a persistent background daemon, deploy `/usr/local/etc/rc.d/dns_pipeline`:

```sh
#!/bin/sh
# PROVIDE: dns_pipeline
# REQUIRE: suricata unbound
# KEYWORD: shutdown

. /etc/rc.subr

name="dns_pipeline"
rcvar="dns_pipeline_enable"
pidfile="/var/run/${name}.pid"
command="/usr/sbin/daemon"
procname="/usr/local/bin/python3"
script="/root/opnsense/dns-exfil/dns_pipeline.py"
command_args="-c -f -p ${pidfile} ${procname} ${script} --audit-file /var/log/sinkhole_audit.log"

load_rc_config $name
: ${dns_pipeline_enable:="NO"}
run_rc_command "$1"

```

Enable and start the service:

```bash
chmod +x /usr/local/etc/rc.d/dns_pipeline
sysrc dns_pipeline_enable="YES"
service dns_pipeline start

```

### Service Restart & State Volatility

Dynamic local zones applied via `unbound-control` exist strictly in memory. If Unbound or OPNsense restarts:

1. Dynamic redirects are cleared from Unbound's zone table.


2. On pipeline initialization, the Arbiter executes `unbound-control list_local_zones` to repopulate existing quarantined zones into memory.


3. Any subsequent exfiltration query from a persistent client is immediately caught and re-sinkholed by the Sieve.



### RAM Disk & File Descriptor Re-Hook Protocol

If `/tmp/ramdisk` is unmounted during maintenance, Suricata loses its file descriptor to `eve-dns.json`. Restore telemetry flow using:

```bash
# 1. Recreate volatile mount & staging file
mkdir -p /tmp/ramdisk
mount -t tmpfs -o size=64M,mode=0755 tmpfs /tmp/ramdisk
touch /tmp/ramdisk/eve-dns.json
chmod 666 /tmp/ramdisk/eve-dns.json

# 2. Re-hook Suricata engine
pluginctl -s suricata restart

# 3. Verify active stream
tail -f /tmp/ramdisk/eve-dns.json

```
