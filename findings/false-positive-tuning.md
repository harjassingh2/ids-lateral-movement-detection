# False Positive Analysis

Not all alerts are real. These are the scenarios that generated the most
false positive risk and how they were addressed.

---

## High Risk Scenarios

| Scenario | False Positive Risk | Cause |
|---|---|---|
| Admin Share Access | High | Legitimate IT admins use C$, ADMIN$ for remote management |
| Living-off-the-Land | High | WMI, PowerShell, SMB are standard admin tools |
| Cloud API Emulation | High | Real cloud traffic (AWS, Azure) looks similar to emulated C2 |
| SMB Enumeration | Medium | Normal Windows browsing generates similar share access patterns |
| SSH Pivot Detection | Medium | Long SSH sessions are normal for developers and sysadmins |
| DNS Tunnelling | Medium | Some legitimate services use long subdomains for CDN routing |

---

## How Each Was Addressed

**Admin Share and LotL**
The traffic is syntactically identical to legitimate administration - tuning
required scoping rules to known admin source IPs and flagging access outside
expected working hours. Without a solid behavioural baseline this cannot be
tuned reliably.

**Cloud API Emulation**
SNI analysis and certificate validation helped distinguish real cloud traffic
from emulated C2. Real AWS and Azure connections present valid certificates
and consistent SNI patterns - emulated traffic often doesn't.

**SSH Pivot**
Added session duration thresholds combined with data volume checks. Interactive
SSH sessions have characteristic traffic patterns - tunnels show low keystroke
volume with asymmetric data flow. Combining both conditions reduced false positives
significantly.

**DNS Tunnelling**
Entropy thresholds on subdomain labels helped. Some legitimate CDN services use
long subdomains - whitelisting known good domains prevented these from firing.

---

## Key Takeaway

False positive rate is as important as detection rate in a real SOC environment.
An alert that fires constantly on legitimate admin activity gets ignored or disabled.
Tuning detection rules against a real baseline of normal traffic is not optional -
it is the difference between a useful detection capability and noise.
