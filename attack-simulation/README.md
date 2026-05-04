# Attack Simulation

14 post-compromise techniques run against the victim VM from Kali Linux, mapped to MITRE ATT&CK.
All traffic captured to PCAP and replayed through both tools for a fair comparison.

---

## Scenarios

| # | Scenario | MITRE Tactic | Technique | Tool Used |
|---|---|---|---|---|
| 1 | Internal Port Scan | Reconnaissance | T1595 | Nmap |
| 2 | ICMP Reconnaissance | Discovery | T1018 | Ping sweep |
| 3 | SMB Enumeration | Discovery | T1021.002 | Metasploit |
| 4 | Service Access | Lateral Movement | T1021 | Metasploit |
| 5 | Admin Share Lateral Movement | Lateral Movement | T1021.002 | Metasploit psexec |
| 6 | SSH Port-Forwarding | Lateral Movement | T1572 | SSH -L/-R flags |
| 7 | SOCKS Proxy Tunnel | Lateral Movement | T1090 | Metasploit + proxychains |
| 8 | HTTPS-Wrapped Pivoting | Lateral Movement | T1572 | HTTPS tunnel |
| 9 | DNS Tunnelling | Command & Control | T1071.004 | Custom DNS simulation |
| 10 | Living-off-the-Land | Defence Evasion | T1059 | WMI, PowerShell, SMB |
| 11 | Encrypted C2 | Command & Control | T1573 | Custom TLS beacon |
| 12 | Jittered C2 Beaconing | Command & Control | T1071 | Custom jittered beacon |
| 13 | Cloud API Emulation | Command & Control | T1102 | Custom API simulation |
| 14 | LLMNR Poisoning | Credential Access | T1557.001 | Responder |

---

## Results

| # | Scenario | Zeek Default | Zeek Custom | Suricata Default | Suricata Custom | Combined |
|---|---|---|---|---|---|---|
| 1 | Port Scan | High | High | Medium | High | Strong |
| 2 | ICMP Recon | High | High | Low | Medium | Partial |
| 3 | SMB Enum | Medium | High | None | Medium | Strong |
| 4 | Service Access | Medium | High | Low | High | Strong |
| 5 | Admin Share | Medium | High | None | High | Strong |
| 6 | SSH Pivot | Medium | High | None | Medium | Strong |
| 7 | SOCKS Tunnel | Medium | High | None | Medium | Strong |
| 8 | HTTPS Pivot | Low | High | None | Medium | Strong |
| 9 | DNS Tunnel | Low | High | Medium | High | Strong |
| 10 | LotL | Medium | High | None | High | Strong |
| 11 | Encrypted C2 | Medium | High | Low | High | Strong |
| 12 | Jittered C2 | Low | High | None | None | Partial |
| 13 | Cloud API | Low | High | High | High | Strong |
| 14 | LLMNR | High | High | None | High | Strong |
