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

### Multi-Process Pipeline Topology
The pipeline runs two decoupled worker processes communicating over an in-memory queue (`multiprocessing.Queue`) to maintain wire-speed processing:
* **The Sieve (Process 1):** Attaches to the active EVE JSON stream in `/tmp/ramdisk/eve-dns.json`. Calculates Shannon entropy $H(X)$, evaluates label length, strips protocol prefixes (RFC validation records), drops hyphenated cloud infrastructure hostnames, and executes pre-queue apex debouncing.
* **The Arbiter (Process 2):** Consumes flagged candidate frames. Compiles query telemetry, sends structured decision payloads to OpenRouter (`inception/mercury-decide:free`), parses single-value confidence probabilities ($P(\text{Exfil})$), and executes dynamic sinkholing commands via `unbound-control`.

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


### Dynamic Containment Sequence
When the model returns **P(Exfil) >= 0.75**, the Arbiter injects containment rules directly into Unbound's running in-memory tree:
```bash
# 1. Create a wildcard redirection zone for the target apex
unbound-control -c /var/unbound/unbound.conf local_zone intruder.internal redirect

# 2. Sinkhole all lookups (*.intruder.internal) to localhost
unbound-control -c /var/unbound/unbound.conf local_data "intruder.internal A 127.0.0.1"

```

---

## 4. Operational Considerations & System Recovery Runbook

### Service Restart & State Volatility

Dynamic local zones applied via `unbound-control` exist strictly in Unbound's in-memory zone table. If the `unbound` service or the OPNsense firewall restarts:

1. Active dynamic redirects are cleared.
2. The Arbiter's deduplication set automatically repopulates existing quarantined zones on initialization via `unbound-control list_local_zones`.
3. If an infected endpoint issues subsequent exfiltration bursts, the Sieve catches the query and re-triggers immediate mitigation.

### RAM Disk & File Descriptor Re-Hook Protocol

If `/tmp/ramdisk` is unmounted or recreated during maintenance, Suricata loses its open file descriptor to `eve-dns.json`. Execute the following sequence to restore telemetry flow:

1. **Recreate Volatile Mount & Staging File:**
```bash
mkdir -p /tmp/ramdisk
mount -t tmpfs -o size=64M,mode=0755 tmpfs /tmp/ramdisk
touch /tmp/ramdisk/eve-dns.json
chmod 666 /tmp/ramdisk/eve-dns.json

```


2. **Re-Hook Suricata Process:**
```bash
pluginctl -s suricata restart

```


3. **Verify Active Stream:**
```bash
tail -f /tmp/ramdisk/eve-dns.json

```
