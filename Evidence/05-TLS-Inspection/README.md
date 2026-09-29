# OPNsense Base TLS/HTTPS Inspection (SSL-Bump) Architecture

## Executive Summary

This directory contains end-to-end evidence validating the configuration, interception mechanics, certificate trust hierarchy, and operational validation of transparent TLS/HTTPS inspection (SSL-Bump) on an OPNsense firewall. It documents how internal client traffic from `WRKSTN-01` is transparently steered via FreeBSD Packet Filter (PF) redirection into Squid proxy, decrypted using a Subordinate Certificate Authority chained directly to an Active Directory Certificate Services (AD CS) Enterprise Root CA, and evaluated prior to upstream egress or subsequent security service chaining.

---

## 1. Test Metadata

* **Security Gateway Node:** `OPNsense.internal` (192.168.10.1) — Firewall / Security Gateway
* **Client Workstation Node:** `WRKSTN-01` (192.168.10.50) — Windows Test Workstation
* **Domain Controller & Root CA:** `DC01` (10.0.2.4) — Active Directory Certificate Services (AD CS)
* **Interception Proxy Engine:** Squid (`squid` v6.x) running on loopback (`127.0.0.1:3129`)
* **Certificate Authority Entity:** `OPNsense-SubCA-Authority` (Enterprise Subordinate CA)
* **Firewall Redirection Mechanism:** FreeBSD Packet Filter (`pf`) Destination NAT (`rdr-to`)
* **Validation Target:** `[https://secure.eicar.org](https://secure.eicar.org)` & Public TLS Endpoints

---

## 2. Evidence Chain of Custody

| Step | Source System | Evidence File / Artifact | Key Findings |
| --- | --- | --- | --- |
| **01. AD CS Subordinate Issuance & Installation** | `DC01` / `OPNsense` | [adcs-subca-issuance](./adcs-subca-issuance.txt) | Subordinate CA CSR issued by `DC01` (`SubCA` template); verified active certificate and private key installed in OPNsense under `/var/squid/ssl`, matching the active serial number and SHA1 hash bound to Squid. |
| **02. Proxy Listener Verification** | `OPNsense` | [squid-socket-status](./squid-socket-status.txt) | Executed sockstat -4 -l \| grep squid; verified Squid listening on `127.0.0.1:3128` (HTTP) and `127.0.0.1:3129` (HTTPS SSL-Bump). |
| **03. PF Redirect Rule Validation** | `OPNsense` | [pf-nat-rules](./pf-nat-rules.txt) | Inspected `/tmp/rules.debug` via `pfctl -sn`; confirmed port forward rule steering TCP 443 from `192.168.10.0/24` to `127.0.0.1:3129`. |
| **04. Domain Trust Inheritance Check** | `WRKSTN-01` | [cert-trust-verification](./cert-trust-verification.txt) | Executed `Get-ChildItem Cert:\LocalMachine\Root`; confirmed domain-joined trust inheritance from AD CS without manual endpoint provisioning. |
| **05. Decryption & Leaf Forgery Check** | `WRKSTN-01` | [tls-leaf-cert-inspect](./tls-leaf-cert-inspect.txt) | Queried remote TLS endpoint in PowerShell; confirmed leaf certificate issuer reflects chained `CN=OPNsense-SubCA-Authority` with zero browser/OS warnings. |
| **06. Plaintext Access Log Audit** | `OPNsense` | [squid-access-logs](./squid-access-logs.txt) | Monitored `/var/log/squid/access.log`; validated full URI logging (path and query strings) rather than opaque `CONNECT` tunnels. |

---

## 3. Deep-Dive Analysis: TLS Interception & Decryption Engine

### Transparent Redirection & Packet Steering (`pf`)

Client traffic from `WRKSTN-01` destined for external TCP 443 endpoints is redirected at the kernel level without manual proxy configuration:

* **NAT Redirect Target:** Outbound TCP 443 traffic matching the internal interface is captured and redirected to `127.0.0.1:3129` via `rdr-to`.
* **State Preservation:** Squid queries the local PF state table via `getsockname()` and `/dev/pf` to recover the original destination IP and port before initiating the upstream TLS session.

### Squid SSL-Bump Core Mechanics

When an outbound HTTPS request hits the proxy listener:

1. **Upstream Negotiation:** Squid initiates an independent TLS handshake to the real upstream destination, validating the remote server's certificate chain, expiration, and Subject Alternative Names (SANs).
2. **Dynamic Leaf Certificate Generation:** Using `OPNsense-SubCA-Authority`, Squid constructs a synthetic leaf certificate mirroring the upstream Common Name (CN) and SAN attributes.
3. **Downstream Termination:** Squid terminates the client TLS handshake against `WRKSTN-01` using this synthetic certificate, establishing an unencrypted, plaintext HTTP stream in-memory.
4. **Service Adaptation Ready:** The decrypted stream is staged for evaluation by local Access Control Lists (ACLs) or downstream ICAP inspection brokers.

### Client Certificate Inspection Verification Script

```powershell
# Verify TLS interception by querying certificate issuer attributes on WRKSTN-01
$uri = "https://secure.eicar.org"
$webRequest = [System.Net.HttpWebRequest]::Create($uri)
$webRequest.AllowAutoRedirect = $false
try {
    $response = $webRequest.GetResponse()
    $response.Dispose()
} catch {
    # Suppress HTTP errors to inspect negotiated cert
}

$cert = $webRequest.ServicePoint.Certificate
[PSCustomObject]@{
    TargetURI        = $uri
    Subject          = $cert.Subject
    Issuer           = $cert.Issuer
    Thumbprint       = $cert.GetCertHashString()
    InterceptActive  = ($cert.Issuer -like "*OPNsense-SubCA-Authority*")
} | Format-List

```

---

## 4. PKI Trust Architecture: AD CS Subordinate CA Integration

```text
       [ Active Directory Certificate Services (AD CS) ]
                    (Enterprise Root CA on DC01)
                                 │
         Signed CSR via Subordinate Certification Authority Template
                                 ▼
              [ OPNsense-SubCA-Authority (Intermediate) ]
                  (Private Key Resident on OPNsense)
                                 │
            Dynamically Signs Synthetic Leaf Certificates
                                 ▼
                     [ *.eicar.org / *.google.com ]
                                 ▲
                                 │
          Auto-Trusted via Domain GPO / Active Directory Store
                                 │
                     [ Client: WRKSTN-01 ]

```

### Subordinate CA CSR Generation & AD CS Signing

Rather than deploying an untrusted self-signed root authority requiring manual distribution to every client, OPNsense operates as an intermediate Subordinate CA subordinate to an internal Active Directory Certificate Services (AD CS) hierarchy:

1. **CSR Generation on OPNsense:**
* A Certificate Signing Request (CSR) is generated under **System $\rightarrow$ Trust $\rightarrow$ Authorities** with the Common Name `OPNsense-SubCA-Authority`.
* Key usage is explicitly restricted to `Certificate Signing` and `CRL Signing` with CA Basic Constraints enabled (`IsCA=True`).


2. **AD CS Issuance:**
* The CSR is submitted to the AD CS Enterprise Root CA on `DC01` against the standard **Subordinate Certification Authority** certificate template:
```cmd
certreq -submit -attrib "CertificateTemplate:SubCA" opnsense_subca.req opnsense_subca.cer

```


* The certificate is signed, issued by the Root CA, and exported along with the complete CA public trust chain.


3. **Import to OPNsense Trust Store:**
* The issued certificate (`opnsense_subca.cer`) is re-imported under **System $\rightarrow$ Trust $\rightarrow$ Authorities**, completing the cryptographic link between Squid's signing engine and the organization's root of trust.



### Enterprise Trust Inheritance

Because `WRKSTN-01` is joined to the Active Directory domain, the Enterprise Root CA certificate is automatically published to the local machine's `Cert:\LocalMachine\Root` store via Active Directory auto-enrollment and Group Policy (GPO):

* **Zero Client Configuration:** No certificates need to be manually imported on client machines, eliminating deployment friction.
* **Cryptographic Path Validation:** When Squid presents a synthetic leaf certificate signed by `OPNsense-SubCA-Authority`, Windows automatically builds the certificate chain to the AD CS Enterprise Root CA and marks the session fully trusted without security warnings.
