# Detecting Lateral Movement in Enterprise Networks
### Zeek + Suricata | 14 Attack Scenarios | MITRE ATT&CK Mapped

Final year dissertation project — BSc Ethical Hacking and Cyber Security, Coventry University (2:1)

---

## What This Project Is

I built a virtual enterprise network and tested whether open-source IDS tools could
detect an attacker moving through it after initial compromise.

I ran 14 real attack techniques, compared Zeek and Suricata using default configs vs
custom-built detection rules, and measured what each tool caught, missed, and
falsely flagged.

**The headline finding:** Default IDS configs missed most of the hard scenarios.
Custom detection engineering changed that significantly.

---

## The Setup

- 3 VMs: Kali Linux (attacker), Windows (victim), Ubuntu (Zeek monitor)
- Internal monitored network segment — separate from management traffic
- All attack traffic captured to PCAP and replayed through both tools for fair comparison
- Baseline of normal traffic generated first to enable meaningful false positive testing

---

## Scenarios Tested

| # | Scenario | MITRE Technique |
|---|---|---|
| 1 | Internal Port Scan | T1595 |
| 2 | ICMP Reconnaissance | T1018 |
| 3 | SMB Enumeration | T1021.002 |
| 4 | Service Access | T1021 |
| 5 | Admin Share Lateral Movement | T1021.002 |
| 6 | SSH Port-Forwarding | T1572 |
| 7 | SOCKS Proxy Tunnel | T1090 |
| 8 | HTTPS-Wrapped Pivoting | T1572 |
| 9 | DNS Tunnelling | T1071.004 |
| 10 | Living-off-the-Land (LotL) | T1059 |
| 11 | Encrypted C2 | T1573 |
| 12 | Jittered C2 Beaconing | T1071 |
| 13 | Cloud API Emulation | T1102 |
| 14 | LLMNR Poisoning | T1557.001 |

---

## Key Results

- **13 of 14 scenarios** showed significantly better detection with custom rules vs defaults
- **Zeek + Suricata combined** outperformed either tool alone in every hard scenario
- **Jittered C2** was the only scenario where detection remained partial even after tuning
  — timing evasion beat threshold-based logic
- **Highest false positive risk:** LotL and Admin Share scenarios — the traffic is
  identical to legitimate IT administration

---

## Repo Structure

| Folder | What's Inside |
|---|---|
| `lab-setup/` | Network topology, VM config, why dual interfaces mattered |
| `attack-simulation/` | How each scenario was run and what the traffic looked like |
| `detection-rules/` | Custom Zeek scripts and Suricata rules with explanations |
| `findings/` | What default IDS missed, results table, false positive analysis |

---

## Tools Used

Zeek · Suricata · Metasploit · Nmap · Responder · Wireshark · Tcpdump · VMware
