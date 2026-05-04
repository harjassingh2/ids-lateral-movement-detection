# What Default IDS Missed

Summary of where default Zeek and Suricata configurations produced no alert
across the 14 scenarios tested.

---

## Suricata - Default Rule Gaps

| Scenario | Default Result | Why It Failed |
|---|---|---|
| SMB Enumeration | No alert | Looks identical to normal Windows file browsing |
| Admin Share Access | No alert | Uses a legitimate Windows feature with valid credentials |
| SSH Port-Forwarding | No alert | Encrypted — payload cannot be inspected |
| SOCKS Proxy Tunnel | No alert | Blends into normal TCP connection patterns |
| HTTPS-Wrapped Pivoting | No alert | Indistinguishable from normal HTTPS traffic |
| Living-off-the-Land | No alert | Native Windows tools — no malware signature exists |
| Encrypted C2 | Low visibility | Encrypted payload, no known C2 signature to match |
| Jittered C2 | No alert | Randomised timing broke all threshold-based rules |

---

## Zeek — Default Visibility Gaps

Zeek's default logs provided more coverage than Suricata out of the box, but still
had gaps in the hardest scenarios without custom scripts.

| Scenario | Default Result | Why It Was Limited |
|---|---|---|
| HTTPS-Wrapped Pivoting | Low visibility | TLS logs present but no script to surface anomalies |
| DNS Tunnelling | Low visibility | Queries logged but no frequency or entropy analysis |
| Jittered C2 | Low visibility | Connections logged but no behavioural pattern flagged |
| Cloud API Emulation | Low visibility | Traffic logged but no script distinguishing mimicry |

---

## The Core Problem

Default IDS tools are built around known signatures — exploit strings, malware hashes,
blacklisted IPs. Post-compromise lateral movement doesn't look like any of those.
An attacker using valid credentials over SMB, SSH, or HTTPS leaves no signature to match.

Custom detection engineering — behavioural thresholds, protocol metadata analysis,
and multi-log correlation — was required to close these gaps.
