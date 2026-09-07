# Architecture Design Record: Virtualized AD Exploitation & Detection Lab

**Date:** 2026-09-07  
**Status:** In Progress / Baseline Functional  
**Platform:** OPNsense on VirtualBox  

---

## 1. Executive Summary & Purpose

The objective of this laboratory is to build an isolated, multi-tier adversarial simulation and detection engineering testbed. The environment facilitates controlled adversary emulation against Active Directory infrastructure while simultaneously capturing deep packet inspection (DPI) telemetry, layer 3/4 state flows, and Suricata intrusion detection alerts without data loss or address obfuscation.

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
| **LAN (Attacker)** | `em1` | `192.168.10.0/24` | Kali offensive platform. Permitted egress to Target tier and WAN; blocked from firewall management (`22, 80, 443`). |
| **OPT1 (Management)** | `em2` | `192.168.56.0/24` (Host-Only) | Dedicated administrative out-of-band access. Strictly reachable only by the hypervisor host system. |
| **OPT2 (Target)** | `em3` | `192.168.20.0/24` | Active Directory Domain Controller and target assets. Blocked from initiating sessions into `LAN` or `OPT1`. Egress to WAN allowed for OS updates. |

---

## 4. Key Architectural Decisions (ADRs)

* **Decision 1: Suricata Engine Binding on Internal Interfaces (`em1`, `em3`)**
  * *Context:* Binding Suricata to WAN obfuscates true source addresses behind Outbound SNAT and completely blinds the engine to internal east-west traffic between `em1` and `em3`.
  * *Resolution:* Suricata is attached via Netmap to `em1` and `em3` only. This preserves true packet attribution for both north-south and east-west movement while keeping the management plane (`em2`) off the capture pipeline.

* **Decision 2: Hypervisor NAT for WAN Transit**
  * *Context:* Bridging over standard 802.11 Wi-Fi or carrier-grade NAT (CGNAT) results in MAC drops, AP client isolation, and unallocated DHCP leases.
  * *Resolution:* Egress is bound to VirtualBox internal NAT engine, presenting a single clean MAC address upstream while OPNsense manages interior routing.

* **Decision 3: Dedicated Out-of-Band Host-Only Management Plane**
  * *Context:* Managing the firewall over the attacker or target networks creates a security risk of self-compromise and confuses rule testing with management access.
  * *Resolution:* OPNsense Web GUI and SSH are bound strictly to `em2` (`192.168.56.2`), isolated from both test subnets.

* **Decision 4: Virtual NIC Offload Mitigation**
  * *Context:* Hardware checksum, TSO, and LRO offloading frequently introduce packet corruption and dropped SYN/ACK packets inside VirtualBox virtual switching.
  * *Resolution:* All hardware acceleration offloads are disabled globally in OPNsense settings.

---

## 5. Planned Testing Scenarios

1. **Phase 1: Network & State Enforcement**
   * Validate boundary drop rules (Kali $\to$ OPNsense management; Target $\to$ Kali).
   * Verify state table tracking (`pfctl -ss`) during stateful return sessions.
2. **Phase 2: Active Directory Identity Exploitation**
   * AS-REP Roasting (`impacket-GetNPUsers`) against accounts with pre-authentication disabled.
   * Kerberoasting (`impacket-GetUserSPNs`) against service accounts with defined SPNs.
   * Unauthenticated and authenticated LDAP reconnaissance via `ldapsearch` and `SharpHound`.
   * Replication rights abuse (DCSync via `impacket-secretsdump`).
3. **Phase 3: Telemetry & Detection Engineering**
   * Correlate `eve.json` alerts against raw network PCAPs.
   * Evaluate rule trigger accuracy for ET Open signatures.
   * Implement automated parsing and alerting pipeline.
