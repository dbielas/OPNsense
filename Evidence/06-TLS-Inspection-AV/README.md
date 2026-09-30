# OPNsense Transparent TLS Inspection & Antivirus Pipeline Validation

## Executive Summary

This directory contains end-to-end evidence validating the configuration, cryptographic trust hierarchy, traffic redirection, and real-time antivirus inspection of an enterprise transparent SSL-Bump deployment on an OPNsense firewall. It demonstrates how outbound HTTPS sessions initiated by a domain-joined Windows workstation (`WRKSTN-01`) are transparently intercepted, decrypted in memory using synthetic leaf certificates signed by an AD CS subordinate authority (`OPNsense-SubCA-Authority`), and scanned for malicious payloads using C-ICAP and ClamAV before delivery.

---

## 1. Test Metadata

* **Firewall / Proxy Gateway:** `OPNsense.internal` (192.168.10.1) — FreeBSD / OPNsense Core
* **Enterprise Root CA:** `hybrid-DC01-CA` (192.168.10.10) — Active Directory Certificate Services (AD CS)
* **Subordinate CA Entity:** `OPNsense-SubCA-Authority` (Subject: `CN=OPNsense Forward Proxy CA, C=NL`)
* **Test Client Node:** `WRKSTN-01` (192.168.10.50) — Windows 11 Enterprise Domain Member
* **Interception Mechanism:** FreeBSD Packet Filter (`pf`) Port Redirection (`127.0.0.1:3129`) with `/dev/pf` NAT state tracking
* **Inspection Engines:** Squid Proxy (SSL-Bump), C-ICAP Service (`srv_clamav`), ClamAV Engine
* **Target Verification Endpoint:** `https://secure.eicar.org/eicar.com.txt`

```
                     ┌────────────────────────────────────────────────────────┐
                     │              OPNsense Security Gateway                 │
                     │                                                        │
[ WRKSTN-01 ]        │  ┌───────────┐    rdr    ┌───────────┐                 │        [ Origin WAN ]
192.168.10.50        │  │  PF (NAT) │ ────────> │   Squid   │                 │        89.238.73.97:443
 (Windows 11)        │  └───────────┘ :443->3129│ (SSL-Bump)│                 │     (secure.eicar.org)
      │              │         │                └─────┬─────┘                 │              │
      │  Downstream  │         │ /dev/pf              │ Decrypted             │  Upstream    │
      │  TLS Session │         │ DIOCNATLOOK          │ Stream                │  TLS Session │
      │  (Synthetic) │         ▼                      ▼                       │  (Public CA) │
      ├──────────────┼─────────────────────────>┌───────────┐                 ├──────────────┤
      │              │                          │   C-ICAP  │                 │              │
      │              │                          └─────┬─────┘                 │              │
      │              │                                │ In-Memory             │              │
      │              │                                ▼ Scan                  │              │
      │              │                          ┌───────────┐                 │              │
      │              │                          │  ClamAV   │                 │              │
      │              │                          └───────────┘                 │              │
      │              └────────────────────────────────────────────────────────┘              │
      ▼                                                                                      ▼
[ Root Store: hybrid-DC01-CA ]                                                   [ Public Trust Anchor ]

```


---

## 2. Evidence Chain of Custody

| Step | Source System | Evidence File / Artifact | Key Findings |
| --- | --- | --- | --- |
| **01. Subordinate CA Issuance** | `DC01` | [adcs-subca-issuance.txt](https://www.google.com/search?q=./adcs-subca-issuance.txt) | Verified SubCA CSR signing by `hybrid-DC01-CA`; confirmed `Basic Constraints: IsCA=True` and key usage permissions. |
| **02. Packet Filter Redirection** | `OPNsense` | [pf-nat-rules.txt](https://www.google.com/search?q=./pf-nat-rules.txt) | Inspected `/tmp/rules.debug`; verified PF NAT redirecting outbound client TCP 443 traffic to loopback port `3129`. |
| **03. Interception Socket Listeners** | `OPNsense` | [sockstat-listeners.txt](https://www.google.com/search?q=./sockstat-listeners.txt) | Executed `sockstat -4 -l`; confirmed Squid listening on `127.0.0.1:3129` and C-ICAP daemon listening on `127.0.0.1:1344`. |
| **04. Domain Trust Inheritance** | `WRKSTN-01` | [gpo-root-trust.txt](https://www.google.com/search?q=./gpo-root-trust.txt) | Queried `Cert:\LocalMachine\Root`; confirmed `hybrid-DC01-CA` enterprise root certificate inherited via Group Policy. |
| **05. Dynamic Leaf Forgery & Trust** | `WRKSTN-01` | [tls-leaf-cert-inspect.txt](https://www.google.com/search?q=./tls-leaf-cert-inspect.txt) | Inspected negotiated TLS handshake for `secure.eicar.org`; verified synthetic leaf signed by `OPNsense Forward Proxy CA` with valid browser path validation. |
| **06. Plaintext Access Log Audit** | `OPNsense` | [squid-access-logs.txt](https://www.google.com/search?q=./squid-access-logs.txt) | Inspected `/var/log/squid/access.log`; verified `GET` plaintext URI logging and `ORIGINAL_DST/89.238.73.97` state recovery. |
| **07. In-Line Antivirus Interception** | `OPNsense, WRKSTN-01` | [clamav-virus-block.txt](https://www.google.com/search?q=./clamav-virus-block.txt) | Verified ClamAV and C-ICAP blocked `eicar.com.txt`; confirmed Squid served HTTP 403 infection page and logged signature detection. |

---

## 3. Deep-Dive Analysis: Interception Architecture & AV Inspection Engine

### Kernel-Level Redirection & State Recovery (`/dev/pf`)

Transparent interception does not require manual proxy configurations on the client. Outbound traffic steering and state preservation follow a strict path:

* **Packet Redirection:** PF captures egress TCP 443 packets from the client subnet and redirects them to Squid's local interception socket:
```text
rdr on em0 proto tcp from 192.168.10.0/24 to !<internal_nets> port 443 -> 127.0.0.1 port 3129

```


* **Original Destination Preservation:** Because port redirection modifies the destination IP at the socket layer to `127.0.0.1`, Squid queries `/dev/pf` via the FreeBSD `DIOCNATLOOK` `ioctl` call. This retrieves the original public destination IP (`ORIGINAL_DST/89.238.73.97`), preventing connection blackholing.

### TLS Termination & Dynamic Leaf Generation

Squid terminates two independent cryptographic handshakes:

1. **Upstream Handshake:** Squid initiates an outbound TLS connection to the public origin server (`secure.eicar.org`), validates the external certificate chain, and reads the Subject Alternative Names (SANs).
2. **Synthetic Leaf Forgery:** Squid's helper daemon (`security_file_certgen`) generates a matching leaf certificate dynamically and signs it using the intermediate private key (`OPNsense Forward Proxy CA`).
3. **Downstream Handshake:** The generated certificate is served to `WRKSTN-01`. Because `hybrid-DC01-CA` is pre-installed in the workstation's Trusted Root store via GPO, the client validates the synthetic certificate transparently.

### Content Adaptation & ClamAV Inspection Pipeline

Once decrypted into raw HTTP in memory:

1. **Stream Forwarding to C-ICAP:** Squid routes the unencrypted HTTP response body over local socket `127.0.0.1:1344` using the ICAP protocol (`icap://127.0.0.1:1344/srv_clamav`).
2. **Signature Evaluation:** The `srv_clamav` service streams the payload into the ClamAV scanning engine.
3. **Interception Verdict:**
* **Clean Traffic:** Payload streams back to Squid and is re-encrypted downstream to the client.
* **Malicious Signature Detected:** C-ICAP halts downstream transmission, returns an ICAP block response, and instructs Squid to substitute the payload with a customized HTTP `403 Forbidden` virus notification page.



### Dynamic Leaf Inspection Script

```powershell
$targetUri = "https://secure.eicar.org"
$webRequest = [System.Net.HttpWebRequest]::Create($targetUri)
$webRequest.AllowAutoRedirect = $false

try {
    $response = $webRequest.GetResponse()
    $response.Dispose()
} catch {
    # Suppress HTTP status exceptions to inspect negotiated SSL/TLS stream
}

$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$webRequest.ServicePoint.Certificate
[PSCustomObject]@{
    TargetURI        = $targetUri
    Subject          = $cert.Subject
    Issuer           = $cert.Issuer
    Thumbprint       = $cert.Thumbprint
    InterceptActive  = ($cert.Issuer -like "*OPNsense Forward Proxy CA*")
} | Format-List

```

---

## 4. Operational Considerations & Troubleshooting Runbook

### Authority Information Access (AIA) & PartialChain Validation

* **Behavior:** Web browsers (Edge, Chrome) successfully validate synthetic leaf certificates, whereas raw .NET / PowerShell scripts (`X509Chain.Build()`) may return `PartialChain: A certificate chain could not be built to a trusted root authority`.
* **Root Cause:** Browsers support dynamic AIA chasing and local intermediate certificate caching, whereas Windows .NET CryptoAPI validates strictly against the machine store (`Cert:\LocalMachine\CA`) by default.
* **Remediation:** Ensure the intermediate Subordinate CA certificate is published domain-wide to the enterprise Intermediate Certification Authorities container via Active Directory:
```cmd
certutil -dspublish -f opnsense_subca.cer SubCA

```



### Squid Query Parameter Truncation (`strip_query_terms`)

* **Behavior:** Requests containing query strings (e.g., `?nocache=12345`) appear in `/var/log/squid/access.log` with a trailing `?` and omitted parameters.
* **Operational Cause:** Squid enables `strip_query_terms on` by default to prevent logging sensitive user tokens, passwords, or session IDs in plaintext. Cache busting functions normally inside the engine despite log sanitation.

### ClamAV Memory Exhaustion Recovery Protocol

If high memory pressure on FreeBSD causes ClamAV (`clamd`) or C-ICAP to terminate, uninspected HTTPS traffic may fail open or trigger connection reset errors. Execute the following service recovery sequence via the OPNsense shell:

1. **Verify Daemon Socket States:**
```sh
sockstat -4 -l | grep -E "clamd|c-icap"

```


2. **Cycle Content Security Services:**
```sh
configctl clamav restart
configctl cicap restart
configctl webgui restart

```


3. **Verify Proxy Service Re-Attachment:**
```sh
tail -n 20 /var/log/c-icap/server.log

```
