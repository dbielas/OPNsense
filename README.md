# Architecture Design Record: Virtualized AD Exploitation & Detection Lab

**Date:** 2026-09-07  
**Status:** Baseline Functional / Active Detection & Containment Validation  
**Platform:** OPNsense on VirtualBox  

---

## 1. Executive Summary & Purpose

The objective of this laboratory is to build an isolated, multi-tier adversarial simulation and detection engineering testbed. The environment facilitates controlled adversary emulation against Active Directory infrastructure while simultaneously capturing deep packet inspection (DPI) telemetry, Layer 3/4 state flows, and Suricata intrusion detection alerts without data loss or address obfuscation.

---

## 2. Core Objectives

1. **Adversarial Emulation & Telemetry Capture:**
   * Execute real-world Active Directory exploitation techniques (Kerberoasting, AS-REP roasting, DCSync/DRSUAPI abuse, LDAP enumeration via BloodHound/SharpHound).
   * Evaluate IDS/IPS signature fidelity against adversary playbooks without false positives on legitimate administrative channels.

2. **Network Segmentation & Zero-Trust Boundary Defense:**
   * Enforce strict L3/L4 policy controls between the attacker tier, the target/sandbox tier, the firewall management plane, and upstream internet egress.
   * Model enterprise segmentation: stateful inspection allows Kali-initiated reconnaissance and attacks while disallowing target-initiated sessions into the attacker subnet.

3. **High-Fidelity Telemetry Preservation (Pre-NAT):**
   * Capture raw internal IP addresses for all east-west and north-south sessions to prevent NAT-induced attribution collapse.
   * Centralize and structure raw engine logs (`eve.json`) for downstream ingestion into a SIEM/security data lake.

4. **Self-Contained & Transportable Infrastructure:**
   * Provide consistent testing capabilities over any upstream network (including strict CGNAT, guest portals, and wireless networks) by decoupling hypervisor management from physical NIC bridging.

---

## 3. Network Architecture & Segmentation

| Segment / Zone | Interface | Subnet / Mask | Role & Security Posture |
| :--- | :--- | :--- | :--- |
| **WAN** | `em0` | `10.0.2.0/24` (Hypervisor NAT) | Egress-only for updates, NTP, and package repos. Direct inbound traffic denied. |
| **LAN (Attacker / Client)** | `em1` | `192.168.10.0/24` | Kali offensive platform and client test workstation (`WRKSTN-01` for TLS/AV/DLP validation). Permitted egress to Target tier and WAN; blocked from firewall management (`22, 80, 443`). |
| **OPT1 (Management)** | `em2` | `192.168.56.0/24` (Host-Only) | Dedicated administrative out-of-band access. Strictly reachable only by the hypervisor host system. |
| **OPT2 (Target)** | `em3` | `192.168.20.0/24` | Active Directory Domain Controller (`DC01`) and domain-joined target/endpoint assets. Blocked from initiating sessions into `LAN` or `OPT1`. Egress to WAN allowed for OS updates. |

---

## 4. Key Architectural Decisions (ADRs)

* **Decision 1: Suricata Engine Binding on Internal Interfaces (`em1`, `em3`)**
  * *Context:* Binding Suricata to WAN obfuscates true source addresses behind outbound SNAT and completely blinds the engine to internal east-west traffic between `em1` and `em3`.
  * *Resolution:* Suricata is attached via Netmap to `em1` and `em3` only. This preserves true packet attribution for both north-south and east-west movement while keeping the management plane (`em2`) off the capture pipeline.

* **Decision 2: Hypervisor NAT for WAN Transit**
  * *Context:* Bridging over standard 802.11 Wi-Fi or carrier-grade NAT (CGNAT) results in MAC drops, AP client isolation, and unallocated DHCP leases.
  * *Resolution:* Egress is bound to the VirtualBox internal NAT engine, presenting a single clean MAC address upstream while OPNsense manages interior routing.

* **Decision 3: Dedicated Out-of-Band Host-Only Management Plane**
  * *Context:* Managing the firewall over the attacker or target networks creates a security risk of self-compromise and confuses rule testing with management access.
  * *Resolution:* OPNsense Web GUI and SSH are bound strictly to `em2` (`192.168.56.2`), isolated from both test subnets.

* **Decision 4: Virtual NIC Offload Mitigation**
  * *Context:* Hardware checksum, TSO, and LRO offloading frequently introduce packet corruption and dropped SYN/ACK packets inside VirtualBox virtual switching.
  * *Resolution:* All hardware acceleration offloads are disabled globally in OPNsense settings.

---

## 5. Executed Testing Phases & Evidence Index

1. **Phase 1: Active Directory Exploitation & NIDS/IPS Detection**
   * [01 - AS-REP Roasting & Kerberoasting Mitigation](Evidence/01-AS-REP/README.md): Unauthenticated TGT harvesting (`impacket-GetNPUsers`), Event ID `4768` + Suricata correlation, and Server 2025 `KDC_ERR_ETYPE_NOSUPP` RC4 mitigation.
   * [02 - LDAPS Enumeration](Evidence/02-LDAP-Enumeration/README.md): Encrypted BloodHound/NetExec enumeration over TCP 636, Suricata L4 telemetry, and NTDS Event ID `1644` diagnostics.
   * [03 - DCSync & Netmap IPS](Evidence/03-DCSync/README.md): `DRSUAPI` replication abuse (`impacket-secretsdump`), Event ID `4662` correlation, and inline Suricata Netmap `drop` enforcement.
   * [04 - Golden Ticket & EDR Evasion](Evidence/04-Golden-Ticket/README.md): AES-256 TGT forgery (`impacket-ticketer`) and WinRM LotL execution (`evil-winrm`) bypassing Defender behavioral blocks on `smbexec.py`.

2. **Phase 2: Transparent TLS Inspection, AV & DLP**
   * [05 - Base TLS/HTTPS Inspection](Evidence/05-TLS-Inspection/README.md): FreeBSD `pf` `rdr-to` steering into Squid SSL-Bump backed by an AD CS Subordinate CA.
   * [06 - In-Line Antivirus Interception](Evidence/06-TLS-Inspection-AV/README.md): Squid `RESPMOD` + C-ICAP + ClamAV real-time EICAR payload blocking.
   * [07 - Outbound TLS Inspection & DLP](Evidence/07-TLS-Inspection-DLP/README.md): Squid `REQMOD` + custom ClamAV hex signature blocking outbound sensitive data over HTTPS.

3. **Phase 3: DNS Exfiltration Detection, Attribution & Containment**
   * [08 - Real-Time DNS Exfiltration Detection](Evidence/08-DNS-Exfiltration/README.md): Suricata `tmpfs` EVE tap, two-stage entropy/length sieve, OpenRouter LLM arbitration, and dynamic Unbound sinkholing.
   * [09 - Attribution & Dynamic Host Containment](Evidence/09-DNS-Exfiltration-Containment/README.md): Resolving the AD DNS forwarder blind spot via KQL/`dns.log` correlation and automated L3 host isolation with `pfctl`.
