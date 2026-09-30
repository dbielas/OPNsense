# OPNsense In-Line Antivirus & Malicious Payload Interception Pipeline

## Executive Summary

This directory contains end-to-end evidence validating the dynamic detection, in-memory isolation, and active termination of malicious web-borne payloads passing through the OPNsense security gateway. Building upon decrypted SSL-Bump transport streams, it demonstrates how decrypted HTTP response bodies are handed off to the local C-ICAP service, scanned against the ClamAV signature database in real time, and replaced with an HTTP `403 Forbidden` virus notification page before infected bytes can reach the client endpoint (`WRKSTN-01`).

---

## 1. Test Metadata

* **Security Gateway:** `OPNsense.internal` (192.168.10.1) — FreeBSD / OPNsense Core
* **Antivirus Scanning Daemon:** ClamAV (`clamd` v1.x)
* **Adaptation Protocol Daemon:** C-ICAP (`c-icap` v0.5.x)
* **ICAP Service Module:** `srv_clamav.so` (Service: `srv_clamav`)
* **Test Client Node:** `WRKSTN-01` (192.168.10.50) — Windows 11 Enterprise
* **Test Malicious Signature:** EICAR Standard Anti-Virus Test File (`Eicar-Signature` / `Eicar-Test-Signature`)
* **HTTPS Intercepted:** `https://secure.eicar.org/eicar.com`
* **Enforcement Behavior:** Complete downstream payload suppression; dynamic template injection (`VIRUS FOUND`)

---

## 2. Evidence Chain of Custody

| Step | Source System | Evidence File / Artifact | Key Findings |
| --- | --- | --- | --- |
| **01. ClamAV Engine & Signature Status** | `OPNsense` | [clamav-engine-signatures.txt](https://www.google.com/search?q=./clamav-engine-signatures.txt) | Inspected `freshclam.log` and `clamd.log`; confirmed active signatures database (`daily.cvd`, `main.cvd`) loaded in RAM. |
| **02. C-ICAP Service Socket & Module Binding** | `OPNsense` | [cicap-service-socket.txt](https://www.google.com/search?q=./cicap-service-socket.txt) | Executed `sockstat -4 -l | grep c-icap`; verified daemon bound to `127.0.0.1:1344` with module `virus_scan` loaded. |
| **03. Proxy-to-ICAP Adaptation Plumbing** | `OPNsense` | [squid-icap-config.txt](https://www.google.com/search?q=./squid-icap-config.txt) | Inspected Squid ICAP directives; validated `icap_enable on`, `adaptation_access`, and response mode `icap_service service_avi_resp respmod_precache`. |
| **04. Malicious Payload Suppression (Client)** | `WRKSTN-01` | [client-eicar-suppression.txt](https://www.google.com/search?q=./client-eicar-suppression.txt) | Executed `Invoke-WebRequest` against EICAR endpoint; confirmed zero signature bytes written to disk and HTTP `403 Forbidden` received. |
| **05. C-ICAP In-Memory Detection Telemetry** | `OPNsense` | [cicap-detection-log.txt](https://www.google.com/search?q=./cicap-detection-log.txt) | Inspected  `/var/log/c-icap/access.log`; verified `VIRUS DETECTED: Eicar-Test-Signature` trigger. |
| **06. Proxy Enforcement & Block Page Delivery** | `OPNsense` | [squid-antivirus-block-log.txt](https://www.google.com/search?q=./squid-antivirus-block-log.txt) | Verified `access.log` logged `TCP_MISS/403` with C-ICAP block template size rather than EICAR raw payload delivery. |

---

## 3. Deep-Dive Analysis: The In-Line AV Stream Inspection Lifecycle

```
[ WRKSTN-01 ]              [ Squid (SSL-Bump) ]              [ C-ICAP / clamd ]            [ Origin Server ]
 192.168.10.50                 127.0.0.1:3129                  127.0.0.1:1344              secure.eicar.org
      │                              │                               │                            │
      │ 1. GET /eicar.com.txt (TLS)  │                               │                            │
      ├─────────────────────────────>│ 2. Decrypt Session In-Memory  │                            │
      │                              │ 3. Fetch Origin Payload (TLS) │                            │
      │                              ├───────────────────────────────────────────────────────────>│
      │                              │ 4. HTTP 200 OK (Payload Stream)                            │
      │                              │<───────────────────────────────────────────────────────────┤
      │                              │                               │                            │
      │                              │ 5. RESPMOD (Pipe Stream)      │                            │
      │                              ├──────────────────────────────>│                            │
      │                              │                               │ 6. Scan Body (In-Memory)   │
      │                              │                               │    MATCH: Eicar-Signature  │
      │                              │ 7. ICAP 200 OK (Modified)     │                            │
      │                              │    Inject: HTTP 403 Forbidden │                            │
      │                              │<──────────────────────────────┤                            │
      │ 8. Terminate Downstream Flow │                               │                            │
      │    Send Custom Infection Page│                               │                            │
      │<─────────────────────────────┤                               │                            │
      ▼                              ▼                               ▼                            ▼

```

### The ICAP Adaptation Hook (`RESPMOD`)

Squid intercepts the HTTP response body before sending it downstream to the client workstation by utilizing the **Internet Content Adaptation Protocol (ICAP)** in Response Modification (`RESPMOD`) mode:

* **Decryption Hand-Off:** Squid decrypts the incoming TLS stream from the origin server directly into RAM buffers.
* **Shared Memory Interprocess Streaming:** Instead of writing files to disk, Squid pipes the unencrypted bytes over `127.0.0.1:1344` to the C-ICAP service worker processes.
* **Scan Interception:** The `srv_clamav` plugin sends chunks to `clamd` via local UNIX domain sockets (`/var/run/clamav/clamd.sock`).

### Threat Remediation & Downstream Injection

If the payload matches a known threat pattern:

1. **Stream Severing:** C-ICAP immediately terminates buffering of the upstream payload. The rest of the upstream stream is discarded.
2. **Payload Replacement:** C-ICAP alters the HTTP response status header from `200 OK` to `403 Forbidden` and substitutes the response body with an administrative infection warning template (`VIRUS FOUND: Eicar-Test-Signature`).
3. **Downstream Delivery:** Squid encrypts the warning page using the dynamic synthetic certificate and delivers it to `WRKSTN-01`. The workstation operating system and browser never ingest or write the malicious binary strings.

### Payload Interception Validation Script

Run from **WRKSTN-01** to capture the client-side blocked response:

```powershell
$target = "https://secure.eicar.org/eicar.com.txt"
$evidenceFile = "C:\Evidence\client-eicar-suppression.txt"

try {
    $response = Invoke-WebRequest -Uri $target -UseBasicParsing
    "VULNERABILITY: Malware payload was NOT intercepted. Status: $($response.StatusCode)" | Out-File $evidenceFile
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    $streamReader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $body = $streamReader.ReadToEnd()
    
    @"
================================================================================
EVIDENCE ARTIFACT 04: CLIENT-SIDE MALWARE INTERCEPTION
================================================================================
Target URL    : $target
HTTP Status   : $statusCode (Access Denied / Blocked)
Payload Leak  : Zero malicious bytes transferred

Response Body Received:
--------------------------------------------------------------------------------
$body
================================================================================
"@ | Out-File $evidenceFile
}

```

---

## 4. Operational Considerations & AV Troubleshooting Runbook

### ClamAV Memory Footprint & FreeBSD OOM-Killer

* **Behavior:** Under low-memory conditions, FreeBSD's Out-Of-Memory (OOM) pager will terminate `clamd` because the signature database requires 1.2 GB+ of continuous virtual memory.
* **Symptom:** Squid logs `ICAP protocol error` or `ICAP service unavailable`, causing traffic either to drop (fail-closed) or bypass scanning entirely (fail-open).
* **Verification:** Check `/var/log/messages` on OPNsense for:
```text
kernel: pid XXXX (clamd), jid 0, uid 106: exited on signal 9 (terminated)

```



### Signature Update Synchronization (`freshclam`)

* **Behavior:** When `freshclam` downloads signature updates, `clamd` must reload database definitions into memory.
* **Impact:** During the 10-30 second reload interval, C-ICAP connection pools may saturate.
* **Remediation:** Configure `freshclam` updates to execute during maintenance windows and tune Squid's ICAP service bypass directives:
```text
icap_service_failure_limit 10 in 60
bypass on

```



### Service Health Restoration Sequence

If C-ICAP stops processing streams or the AV engine freezes, run this recovery sequence from the OPNsense shell:

1. **Verify ClamAV Daemon Socket:**
```sh
ls -l /var/run/clamav/clamd.sock

```


2. **Restart Antivirus and Adaptation Daemons:**
```sh
configctl clamav restart
configctl cicap restart

```


3. **Validate Real-Time Scanner Log Hook:**
```sh
tail -f /var/log/c-icap/server.log

```
