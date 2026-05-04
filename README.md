# Why Default IDS Fails Against Lateral Movement

> A comparative detection study using Zeek and Suricata across 14 post-compromise attack scenarios in a controlled virtual enterprise network.

**Tools:** Zeek · Suricata · Metasploit · Wireshark · Tcpdump · VMware  
**Scenarios:** 14 MITRE ATT&CK-mapped attack scenarios  
**Key finding:** Custom detection engineering improved results in 13 of 14 scenarios. Default rulesets alone are insufficient for post-compromise internal threats.

---

## The Problem

Most organisations deploy Suricata or Snort with default community rulesets and assume they have internal threat coverage. Against lateral movement and pivoting, they largely don't.

Default IDS signatures are built around known patterns — exploit strings, malware hashes, blacklisted IPs. An attacker who has already gained access and is moving through an internal network doesn't look like that. They use SMB, SSH, DNS, RDP — the same protocols that legitimate IT administrators use every day. Default rules have no behavioural baseline to compare against, so they stay silent.

This project tested exactly that scenario across 14 real attack techniques in a controlled enterprise lab, comparing Zeek, Suricata, and a combined hybrid approach — both with default configurations and with custom-engineered detection logic.

---

## Lab Environment

A VMware-based virtual enterprise network with three hosts and dual network interfaces:

- **Kali Linux** — attacker machine running Suricata for signature-based monitoring
- **Windows victim VM** — enterprise target with SMB shares, services, and simulated user activity  
- **Ubuntu** — Zeek monitoring station performing behavioural network analysis

Dual interfaces separated management/update traffic from the monitored internal segment, keeping packet captures clean and ensuring all detections were tied to the correct scenarios. All attack traffic was captured to PCAP files and replayed through both tools for repeatable, auditable comparison.

Full configuration in [`lab-setup/`](./lab-setup/).

---

## Attack Scenarios (MITRE ATT&CK Mapped)

14 post-compromise techniques were simulated, ranging from basic reconnaissance to advanced evasion:

| # | Scenario | MITRE Tactic | Technique |
|---|---|---|---|
| 1 | Internal Port Scan | Reconnaissance | T1595 |
| 2 | ICMP Reconnaissance | Discovery | T1018 |
| 3 | SMB Access / Enumeration | Discovery | T1021.002 |
| 4 | Service Access | Lateral Movement | T1021 |
| 5 | Admin Share Analysis | Lateral Movement | T1021.002 |
| 6 | SSH Port-Forwarding | Lateral Movement | T1572 |
| 7 | SOCKS Proxy Tunnel | Lateral Movement | T1090 |
| 8 | HTTPS-Wrapped Pivoting | Lateral Movement | T1572 |
| 9 | DNS Tunnelling | Command & Control | T1071.004 |
| 10 | Living-off-the-Land (LotL) | Defence Evasion | T1059 |
| 11 | Encrypted C2 Traffic | Command & Control | T1573 |
| 12 | Jittered C2 Traffic | Command & Control | T1071 |
| 13 | Cloud API Emulation | Command & Control | T1102 |
| 14 | LLMNR Poisoning | Credential Access | T1557.001 |

Full methodology and scenario design in [`attack-simulation/`](./attack-simulation/).

---

## Detection Approach

Two complementary monitoring strategies were combined:

**Zeek** produces rich behavioural telemetry — connection logs, DNS logs, SMB logs, SSL/TLS metadata, NTLM session data. It doesn't fire alerts from signatures; it generates context that can be scripted into custom detection logic. This makes it particularly effective for scenarios where suspicious behaviour uses legitimate protocols.

**Suricata** provides fast rule-based detection against protocol anomalies and known patterns. Highly effective when suspicious activity has a definable signature — DNS tunnelling, LLMNR poisoning, port scanning. Less effective when the traffic looks identical to legitimate administration.

Custom Zeek scripts and tuned Suricata rules were developed for every scenario, and results were compared against default configurations. Detection rules and scripts in [`detection-rules/`](./detection-rules/).

---

## Key Findings

- **Default rulesets failed silently on the hardest scenarios** — Admin Share Analysis, SSH Port-Forwarding, SOCKS tunnelling, and Living-off-the-Land produced no Suricata default alerts
- **Custom detection engineering made the biggest difference** — 13 of 14 scenarios showed significant improvement with custom logic over defaults
- **The combined approach outperformed either tool alone** — Suricata flagged protocol anomalies fast; Zeek provided the attribution, context, and behavioural correlation to confirm them
- **Jittered C2 was the hardest to detect** — timing-based evasion broke threshold logic in both tools; only partial detection was achieved even after tuning
- **False positives were a real operational challenge** — Living-off-the-Land and Admin Share scenarios had high false positive risk because the traffic is syntactically identical to normal IT administration

Full results analysis in [`findings/`](./findings/).

---

## What I'd Do Next

- Integrate **Sysmon host-side logs** to correlate network-level detection with process execution events — would significantly improve LotL detection
- Replace static thresholds in jittered C2 detection with **dynamic baselines** using Zeek's Summary Statistics framework
- Test against **larger-scale enterprise traffic** to measure alert fatigue and analyst workload under realistic noise levels
- Feed alerts into a **SOAR playbook** to automate initial triage and reduce false positive burden on analysts
- Extend to **east-west encrypted traffic analysis** using JA3/JA3S fingerprinting for TLS-based C2 detection without decryption

---

## Repository Structure

| Folder | Contents |
|---|---|
| [`lab-setup/`](./lab-setup/) | VM configuration, network topology, dual interface design |
| [`attack-simulation/`](./attack-simulation/) | 14 MITRE ATT&CK scenarios, tools used, traffic methodology |
| [`detection-rules/`](./detection-rules/) | Custom Zeek scripts, Suricata rules, plain-English explanations |
| [`findings/`](./findings/) | What default IDS missed, results summary, false positive analysis |
