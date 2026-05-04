# Detection Rules - Overview

Custom Zeek scripts and Suricata rules were written for every scenario.
This file explains what each rule detects and why it works.

---

## Zeek Scripts

Zeek generates behavioural logs — connections, DNS, SMB, TLS, NTLM.
Custom scripts analyse these logs to surface suspicious patterns.

| Script | Scenario | What It Detects |
|---|---|---|
| ICMP recon | Scenario 2 | Single source contacting many destination IPs in a short window |
| Port scan | Scenario 1 | Single source hitting many ports on the same host rapidly |
| SMB enumeration | Scenarios 3, 4, 5 | Broad share enumeration, admin share access, NTLM session linking |
| SSH tunnel | Scenarios 6, 7 | Long sessions with low data volume, flow asymmetry, pivot indicators |
| DNS tunnelling | Scenario 9 | High query frequency, long subdomain strings, high entropy labels |
| Encrypted C2 | Scenarios 11, 12 | Certificate anomalies, session persistence, flow asymmetry in TLS logs |
| LLMNR poisoning | Scenario 14 | Unexpected host answering LLMNR queries not directed at it |

---

## Suricata Rules

Suricata matches on packet headers, protocol fields, and threshold conditions.

| Rule | Scenario | What It Detects |
|---|---|---|
| SYN threshold | Scenario 1 | 20+ SYN packets to different ports from one source within 5 seconds |
| SMB admin share | Scenario 5 | Connections targeting C$, ADMIN$, IPC$ share names |
| DNS query length | Scenario 9 | DNS queries with subdomain labels exceeding normal length thresholds |
| DNS record type | Scenario 9 | Unusual DNS record types (TXT, NULL) at high frequency |
| SSH reconnect | Scenarios 6, 7 | Rapid repeated SSH connections from the same source |
| TLS anomaly | Scenario 11 | Self-signed certificates, missing SNI, direct-IP TLS connections |

---

## Key Insight

Default rules caught the obvious scenarios — port scanning, LLMNR poisoning, DNS tunnelling.
They produced no alerts for Admin Share access, SSH pivoting, SOCKS tunnelling, LotL, or
encrypted C2. Custom engineering was required for all of these.

See `suricata.rules` and `zeek-detection.zeek` for the actual rule and script files.# Detection Rules — Overview

Custom Zeek scripts and Suricata rules were written for every scenario.
This file explains what each rule detects and why it works.

---

## Zeek Scripts

Zeek generates behavioural logs — connections, DNS, SMB, TLS, NTLM.
Custom scripts analyse these logs to surface suspicious patterns.

| Script | Scenario | What It Detects |
|---|---|---|
| ICMP recon | Scenario 2 | Single source contacting many destination IPs in a short window |
| Port scan | Scenario 1 | Single source hitting many ports on the same host rapidly |
| SMB enumeration | Scenarios 3, 4, 5 | Broad share enumeration, admin share access, NTLM session linking |
| SSH tunnel | Scenarios 6, 7 | Long sessions with low data volume, flow asymmetry, pivot indicators |
| DNS tunnelling | Scenario 9 | High query frequency, long subdomain strings, high entropy labels |
| Encrypted C2 | Scenarios 11, 12 | Certificate anomalies, session persistence, flow asymmetry in TLS logs |
| LLMNR poisoning | Scenario 14 | Unexpected host answering LLMNR queries not directed at it |

---

## Suricata Rules

Suricata matches on packet headers, protocol fields, and threshold conditions.

| Rule | Scenario | What It Detects |
|---|---|---|
| SYN threshold | Scenario 1 | 20+ SYN packets to different ports from one source within 5 seconds |
| SMB admin share | Scenario 5 | Connections targeting C$, ADMIN$, IPC$ share names |
| DNS query length | Scenario 9 | DNS queries with subdomain labels exceeding normal length thresholds |
| DNS record type | Scenario 9 | Unusual DNS record types (TXT, NULL) at high frequency |
| SSH reconnect | Scenarios 6, 7 | Rapid repeated SSH connections from the same source |
| TLS anomaly | Scenario 11 | Self-signed certificates, missing SNI, direct-IP TLS connections |

---

## Key Insight

Default rules caught the obvious scenarios — port scanning, LLMNR poisoning, DNS tunnelling.
They produced no alerts for Admin Share access, SSH pivoting, SOCKS tunnelling, LotL, or
encrypted C2. Custom engineering was required for all of these.

See `suricata.rules` and `zeek-detection.zeek` for the actual rule and script files.
