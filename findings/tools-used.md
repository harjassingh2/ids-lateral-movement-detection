# Tools Used

| Tool | Role in Project |
|---|---|
| Zeek | Behavioural network analysis - connection logs, DNS, SMB, TLS, NTLM metadata |
| Suricata | Signature-based IDS - rule matching, protocol anomaly detection, threshold alerting |
| Metasploit | Attack platform - lateral movement, pivoting, and service access scenarios |
| Nmap | Internal port scanning and host discovery scenarios |
| Responder | LLMNR poisoning and NTLM credential capture scenario |
| Wireshark | Packet-level inspection and verification of captured traffic |
| Tcpdump | PCAP capture and transfer between VMs |
| VMware | Virtual lab environment - hosted all three VMs |
| Kali Linux | Attacker VM OS |
| Windows | Victim VM OS - SMB shares, internal services, LLMNR enabled |
| Ubuntu | Zeek monitor VM OS |
| Proxychains | Routing traffic through SOCKS proxy tunnel in Scenario 7 |
