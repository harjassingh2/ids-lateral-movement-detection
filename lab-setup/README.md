# Lab Environment Setup

A controlled VMware-based virtual enterprise network designed to simulate realistic internal east-west traffic patterns, enabling a clean and repeatable comparison of Zeek and Suricata detection performance.

---

## Design Goals

The lab was built around one core problem: most IDS research tests tools against perimeter-style attack traffic. This project needed to test detection of *internal* post-compromise behaviour — lateral movement and pivoting between hosts that already trust each other.

That required three things:
1. A realistic enterprise-style network with multiple hosts and segmented roles
2. Clean separation of monitoring traffic from management/update traffic so captures weren't polluted
3. A stable, repeatable environment where the same traffic could be replayed through multiple tool configurations for fair comparison

---

## Network Topology

Three virtual machines, each with a defined role:

| Host | OS | Role |
|---|---|---|
| Attacker VM | Kali Linux | Attack platform + Suricata (signature-based monitoring) |
| Victim VM | Windows | Enterprise target — SMB shares, internal services, simulated user activity |
| Monitor VM | Ubuntu | Zeek monitoring station — behavioural network analysis |

All hosts were assigned consistent hostnames and static IP addresses throughout the project to prevent attribution confusion across log files and packet captures.

---

## Dual Network Interface Design

One of the most important implementation decisions was the use of **dual network interfaces** on each VM.

Most lab setups mix management traffic (software updates, SSH administration) with experimental traffic on the same interface. This pollutes packet captures with noise unrelated to the scenarios being tested.

This lab separated them:

- **Internal monitored interface (host-only)** — all attack traffic, lateral movement simulations, and detection scenarios ran across this segment. This is what Zeek and Suricata monitored.
- **External management interface (NAT)** — software updates, package installations, and file transfers used this interface only, keeping it completely separate from captures.

This meant every PCAP file collected during experiments contained only traffic relevant to the scenario being tested — no background noise, no ambiguity about what triggered a detection.

---

## PCAP-Based Workflow

Rather than relying solely on live traffic output, all scenario traffic was **captured to PCAP files and replayed offline**.

This was critical to the project's reliability. Live traffic is one-shot and hard to reproduce. By preserving every scenario to PCAP:

- The same traffic could be run through both default and custom configurations of each tool
- Detections could be verified and re-verified after rule tuning
- Results across Zeek and Suricata were directly comparable — both analysed identical traffic, not separately timed live captures
- Evidence was auditable — every detection result traces back to a preserved capture file

The workflow: **capture live → save PCAP → transfer to Ubuntu Zeek system → replay through Zeek → replay through Suricata → compare logs**

---

## Baseline Traffic Generation

Before any attack scenarios were run, a baseline of normal internal activity was generated and captured. This included:

- Benign ICMP communications between hosts
- Normal SMB share enumeration and share access
- Routine internal service communication
- Standard DNS queries

This baseline served two purposes. First, it established what normal east-west traffic looked like in this environment — essential for tuning detection rules without generating excessive false positives. Second, it provided a control layer to evaluate whether detections were operationally meaningful, not just technically possible in an attack-only environment.

---

## IP Configuration

| Host | Internal Interface | External Interface |
|---|---|---|
| Kali (Attacker + Suricata) | Configured — see lab notes | NAT |
| Ubuntu (Zeek Monitor) | Configured — see lab notes | NAT |
| Windows (Victim) | Configured — see lab notes | NAT |

Static addressing was used throughout. Changing IPs between scenarios would have broken log correlation and made cross-tool comparison unreliable.

---

## Tools Installed Per Host

**Kali Linux (Attacker)**
- Metasploit Framework — primary attack platform for lateral movement and pivoting scenarios
- Suricata — signature-based IDS, monitoring internal interface traffic
- Tcpdump — packet capture for saving scenario traffic to PCAP

**Ubuntu (Zeek Monitor)**
- Zeek — behavioural network analysis and custom scripted detection
- Tcpdump — PCAP capture and replay support

**Windows (Victim)**
- SMB file shares enabled
- Internal services running to simulate realistic enterprise service access patterns
- Standard Windows networking — LLMNR enabled (intentionally, as it was a target scenario)

---

## Why This Setup Matters for Detection

The dual-interface design and PCAP replay workflow directly influenced detection quality. Because management traffic never appeared on the monitored segment, every alert Zeek or Suricata generated was tied to a specific scenario. False positives could be evaluated against the known baseline rather than dismissed as lab noise.

This is the same principle used in real enterprise detection engineering: you cannot tune detection rules reliably without first knowing what normal looks like on your network.
