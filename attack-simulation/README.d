# Attack Simulation

14 post-compromise attack scenarios designed around realistic internal enterprise behaviour,
mapped to the MITRE ATT&CK framework. Each scenario was selected specifically because it
represents the kind of activity that default IDS configurations struggle with — traffic that
uses legitimate protocols, valid credentials, or trusted services to avoid detection.

---

## Scenario Selection Rationale

The scenarios were not chosen to demonstrate obvious attacks that any IDS would catch. They
were chosen to probe the boundary where malicious behaviour becomes indistinguishable from
normal IT administration.

An attacker who has already compromised a host inside an enterprise network doesn't send
exploit strings across the wire. They use SMB to access file shares — the same way IT staff
do. They use SSH for port forwarding — the same way developers do. They beacon out over
HTTPS — the same way every browser does. The challenge for defenders is behavioural, not
signature-based.

Scenarios were structured across three difficulty tiers:

- **Low-level** — noisy, detectable with basic rules (port scanning, ICMP reconnaissance)
- **Mid-level** — legitimate protocols misused (SMB lateral movement, SSH pivoting, DNS tunnelling)
- **High-level** — stealth and evasion techniques (encrypted C2, jittered beaconing, LotL, cloud API emulation)

---

## Methodology

All scenarios were executed on the internal monitored network segment between the Kali
attacker VM and the Windows victim VM. Every scenario followed the same workflow:

1. Capture baseline traffic to PCAP before the attack
2. Execute the attack technique from Kali
3. Capture all traffic to a scenario-specific PCAP file
4. Transfer PCAP to the Ubuntu Zeek system
5. Replay through Zeek with default configuration → record results
6. Replay through Zeek with custom scripts → record results
7. Replay through Suricata with default rules → record results
8. Replay through Suricata with custom rules → record results
9. Compare detection performance across all four configurations

This PCAP-based replay approach meant both tools analysed identical traffic — not
separately timed live captures — making the comparison directly valid.

---

## Scenario 1 — Internal Port Scan

**MITRE Tactic:** Reconnaissance  
**Technique:** T1595  
**Tool used:** Nmap (from Kali against victim VM)

An attacker's first step after compromising a host is typically internal discovery —
finding out what other hosts and services exist on the network. A TCP SYN scan was run
against the victim VM to map open ports on the internal segment.

**Why it was included:** Baseline scenario. Both tools should detect this. Used to
validate the lab environment and establish a performance floor before harder scenarios.

**Detection result:** Strong detection from both tools. Suricata flagged SYN scan patterns
directly. Zeek provided connection-level flow data confirming the scan scope and timing.
Combined detection time under 2 seconds.

---

## Scenario 2 — ICMP Reconnaissance

**MITRE Tactic:** Discovery  
**Technique:** T1018  
**Tool used:** Ping sweep from Kali

Live host discovery using ICMP — an attacker mapping which hosts are reachable on the
internal network before deciding where to move next.

**Why it was included:** ICMP is completely legitimate traffic in most enterprise
environments. The challenge is distinguishing a sweep from routine connectivity checks.

**Detection result:** Zeek had high default and custom visibility. Suricata had low default
visibility — ICMP sweeps don't match standard signature patterns. Custom Suricata rules
improved this to medium. Combined result partial with medium confidence.

---

## Scenario 3 — SMB Access and Enumeration

**MITRE Tactic:** Discovery  
**Technique:** T1021.002  
**Tool used:** Metasploit SMB enumeration modules from Kali

SMB share enumeration — an attacker discovering what file shares exist on the victim VM,
what they're named, and whether they're accessible. A prerequisite step before lateral
movement via admin shares.

**Why it was included:** SMB enumeration looks almost identical to normal Windows file
share browsing. Default rules have almost no way to distinguish the two.

**Detection result:** Zeek provided strong SMB mapping logs, file activity events, and
NTLM authentication context. Suricata improved from no default visibility to medium
visibility with custom rules. Combined result strong with high confidence.

---

## Scenario 4 — Service Access

**MITRE Tactic:** Lateral Movement  
**Technique:** T1021  
**Tool used:** Metasploit service access modules

Accessing internal services on the victim VM that an attacker has identified as potentially
useful — RDP, SMB, WMI. The goal is confirming reachability and access rights before
committing to a specific lateral movement path.

**Why it was included:** Internal service access is completely normal behaviour on an
enterprise network. There is no exploit involved — just legitimate protocols used by an
unauthorised user.

**Detection result:** Zeek detected service access patterns through connection and protocol
logs. Custom Suricata rules flagged unusual access frequency. Combined result strong with
high confidence.

---

## Scenario 5 — Admin Share Analysis

**MITRE Tactic:** Lateral Movement  
**Technique:** T1021.002  
**Tool used:** Metasploit psexec module via admin shares (C$, ADMIN$)

Moving laterally from the attacker VM to the victim VM using Windows admin shares —
a classic technique where an attacker uses valid credentials to push and execute a payload
via the hidden administrative SMB shares that exist on every Windows host.

**Why it was included:** Admin share access requires valid credentials and uses a legitimate
Windows feature. Default Suricata rules produce no alert. This scenario directly tests
whether custom detection logic can fill that gap.

**Detection result:** Zeek provided rich context — SMB mapping logs, NTLM session linking,
file activity on admin shares. Suricata had no default visibility but high visibility with
custom rules. Combined result strong with high confidence. False positive risk was high
because legitimate IT administration generates similar traffic.

---

## Scenario 6 — SSH Port-Forwarding

**MITRE Tactic:** Lateral Movement  
**Technique:** T1572  
**Tool used:** SSH with -L / -R flags from Kali

Using SSH port forwarding to create a tunnel from the attacker VM through the victim VM
to reach services on the internal network that weren't directly accessible. This allows
an attacker to route traffic through a compromised host without that traffic appearing
suspicious at the network level — it's just SSH.

**Why it was included:** SSH port forwarding is widely used by developers and system
administrators. It produces no exploit traffic. Default IDS tools have very low visibility
into whether an SSH session is being used for legitimate remote work or as a pivot channel.

**Detection result:** Zeek custom scripts detected unusual SSH session behaviour — tunnel
indicators, flow asymmetry, and session duration anomalies. Suricata had no default
visibility but medium visibility with custom rules. Combined result strong with medium
confidence.

---

## Scenario 7 — SOCKS Proxy Tunnel

**MITRE Tactic:** Lateral Movement  
**Technique:** T1090  
**Tool used:** Metasploit socks_proxy module + proxychains

Establishing a SOCKS proxy through the compromised victim VM, allowing the attacker to
route arbitrary TCP traffic through it — effectively using the victim as a gateway to
the rest of the internal network.

**Why it was included:** SOCKS proxying is a common pivot technique in real-world
intrusions. It produces no obvious anomalous traffic — the proxy traffic blends into
normal connection patterns.

**Detection result:** Zeek custom scripts flagged unusual TCP session patterns and
connection behaviour consistent with proxy use. Suricata improved from no default
visibility to medium with custom rules. Combined result strong with high confidence.

---

## Scenario 8 — HTTPS-Wrapped Pivoting

**MITRE Tactic:** Lateral Movement  
**Technique:** T1572  
**Tool used:** Pivoting tunnelled over HTTPS

Pivot traffic wrapped inside HTTPS — making it appear as normal web traffic to any tool
that can't inspect encrypted content. This scenario tested whether Zeek's TLS metadata
analysis could surface anomalies without decrypting the payload.

**Why it was included:** Encryption is one of the most effective ways to evade network
detection. The challenge is detecting suspicious encrypted sessions using only metadata —
certificate details, session length, flow asymmetry, SNI anomalies.

**Detection result:** Zeek's TLS and SSL logs provided certificate metadata, SNI
information, and session flow data that surfaced behavioural anomalies. Suricata had no
default visibility and only medium custom visibility due to encrypted content. Combined
result strong with medium confidence. Detection time approximately 5 seconds.

---

## Scenario 9 — DNS Tunnelling

**MITRE Tactic:** Command and Control  
**Technique:** T1071.004  
**Tool used:** Custom DNS tunnelling simulation from Kali

Covert communication channel built over DNS — encoding C2 traffic or data exfiltration
inside DNS queries and responses. DNS is almost universally allowed through enterprise
firewalls and rarely inspected at depth.

**Why it was included:** DNS tunnelling is a well-documented but consistently effective
C2 technique. It tests whether the tools can detect high query frequency, long query
strings, and entropy anomalies that distinguish tunnelling from normal DNS resolution.

**Detection result:** One of the strongest combined results. Zeek logged query frequency,
string length, and entropy patterns. Suricata flagged long or unusual queries with custom
rules. Both tools detected the scenario independently. Combined detection time approximately
10 seconds. High confidence.

---

## Scenario 10 — Living-off-the-Land (LotL)

**MITRE Tactic:** Defence Evasion  
**Technique:** T1059  
**Tool used:** Native Windows tools — WMI, PowerShell, SMB

Using built-in Windows administration tools to move laterally and execute commands on the
victim VM. No custom malware, no exploit code — just tools that every Windows system
already has and that IT administrators use every day.

**Why it was included:** LotL is one of the hardest detection problems in enterprise
security. The traffic is syntactically identical to legitimate administration. Detection
must rely entirely on context — who is doing it, when, from where, and whether it fits
normal behaviour patterns.

**Detection result:** Zeek custom scripts provided the context needed — SMB session
mapping, NTLM linking, and behavioural correlation across multiple log types. Suricata
had no default visibility and required significant custom rule engineering to reach high
visibility. False positive risk was the highest of any scenario — legitimate IT
administration generates nearly identical traffic.

---

## Scenario 11 — Encrypted C2 Traffic

**MITRE Tactic:** Command and Control  
**Technique:** T1573  
**Tool used:** Custom encrypted C2 beacon simulation over TLS

A C2 channel using TLS encryption to hide the payload from inspection. Regular beaconing
intervals, encrypted content, and valid-looking TLS handshakes designed to blend into
normal HTTPS traffic.

**Why it was included:** Encrypted C2 is the standard for modern malware. Testing whether
Zeek's TLS metadata — certificate details, session duration, connection frequency, flow
symmetry — can surface C2 behaviour without decryption.

**Detection result:** Zeek detected all triggers through TLS log analysis — certificate
anomalies, session persistence, and flow patterns inconsistent with normal HTTPS. Suricata
had low default visibility but high visibility with custom rules targeting TLS anomalies.
Combined result strong with high confidence. Detection time under 2 seconds.

---

## Scenario 12 — Jittered C2 Traffic

**MITRE Tactic:** Command and Control  
**Technique:** T1071  
**Tool used:** Custom jittered beacon simulation — randomised intervals

The same encrypted C2 channel as Scenario 11, but with randomised (jittered) timing
between beacons. Instead of regular intervals that a threshold rule would catch, the
beacon fires at unpredictable intervals designed to evade time-based detection logic.

**Why it was included:** Jittered beaconing is specifically designed to defeat the
threshold-based detection that most IDS tools rely on. This was the hardest scenario
in the test set and the most revealing about the limits of both tools.

**Detection result:** The weakest result in the entire evaluation. Timing evasion broke
Suricata's fixed-threshold logic entirely — no detection even after custom rule
development. Zeek custom scripts provided partial detection through persistent destination
behaviour and connection persistence indicators. Combined result partial with medium
confidence. One example connection of 936.65 seconds duration was detected. This scenario
represents the current ceiling of what this hybrid detection model can achieve.

---

## Scenario 13 — Cloud API Emulation

**MITRE Tactic:** Command and Control  
**Technique:** T1102  
**Tool used:** Custom traffic simulation mimicking cloud service API calls

C2 traffic designed to look like legitimate calls to cloud services — mimicking the
headers, timing, and patterns of normal API traffic to services like AWS, Azure, or
Google. Designed to blend into the background noise of any modern enterprise network
where cloud service traffic is constant and expected.

**Why it was included:** Blending C2 into trusted cloud service traffic is an increasingly
common evasion technique. It tests whether SNI analysis, connection context, and header
anomalies can surface mimicry without blocking legitimate cloud traffic.

**Detection result:** Suricata had strong default visibility — cloud API mimicry produced
detectable header anomalies. Zeek provided SNI and TLS connection context that helped
distinguish legitimate API traffic from emulation. Combined result strong with medium
confidence. High false positive risk — real cloud traffic is similar enough to generate
noise. Detection time approximately 5 seconds.

---

## Scenario 14 — LLMNR Poisoning

**MITRE Tactic:** Credential Access  
**Technique:** T1557.001  
**Tool used:** Responder (from Kali)

Link-Local Multicast Name Resolution (LLMNR) poisoning — intercepting Windows name
resolution requests on the local network and responding with the attacker's IP to capture
NTLM credential hashes. A passive technique that requires no exploit and produces no
obvious anomalous traffic beyond the rogue LLMNR response.

**Why it was included:** LLMNR poisoning is one of the most common techniques in real
internal penetration tests. It's fast, passive, and highly effective on networks where
LLMNR hasn't been explicitly disabled. It was also the strongest detection result in the
entire test set — validating that some credential theft techniques are very detectable
with the right rules.

**Detection result:** The strongest combined result. Zeek had high default and custom
visibility through protocol logs. Suricata custom rules detected rogue LLMNR responses
directly. Combined result strong with high confidence. Detection time under 1 second.
Low false positive risk.

---

## Results Summary

| Scenario | Zeek Default | Zeek Custom | Suricata Default | Suricata Custom | Combined |
|---|---|---|---|---|---|
| 1 — Port Scan | High | High | Medium | High | Strong |
| 2 — ICMP Recon | High | High | Low | Medium | Partial |
| 3 — SMB Enum | Medium | High | None | Medium | Strong |
| 4 — Service Access | Medium | High | Low | High | Strong |
| 5 — Admin Share | Medium | High | None | High | Strong |
| 6 — SSH Pivot | Medium | High | None | Medium | Strong |
| 7 — SOCKS Tunnel | Medium | High | None | Medium | Strong |
| 8 — HTTPS Pivot | Low | High | None | Medium | Strong |
| 9 — DNS Tunnel | Low | High | Medium | High | Strong |
| 10 — LotL | Medium | High | None | High | Strong |
| 11 — Encrypted C2 | Medium | High | Low | High | Strong |
| 12 — Jittered C2 | Low | High | None | None | Partial |
| 13 — Cloud API | Low | High | High | High | Strong |
| 14 — LLMNR | High | High | None | High | Strong |

Detection rules and scripts for every scenario in [`../detection-rules/`](../detection-rules/).  
Full results analysis and false positive observations in [`../findings/`](../findings/).
