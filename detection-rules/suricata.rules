# Custom Suricata Rules
# Project: Detecting Lateral Movement in Enterprise Networks
# Each rule targets a specific scenario - see rules-explained.md for context

# ---------------------------------------------------------------
# Scenario 1 — Internal Port Scan (T1595)
# ---------------------------------------------------------------
alert tcp $HOME_NET any -> $HOME_NET any (msg:"LATERAL-MOV Internal Port Scan Detected"; \
flags:S; threshold:type threshold, track by_src, count 20, seconds 5; \
sid:1000001; rev:1;)

# ---------------------------------------------------------------
# Scenario 5 — Admin Share Access (T1021.002)
# ---------------------------------------------------------------
alert smb any any -> $HOME_NET 445 (msg:"LATERAL-MOV SMB Admin Share Access - ADMIN$"; \
content:"ADMIN$"; nocase; sid:1000002; rev:1;)

alert smb any any -> $HOME_NET 445 (msg:"LATERAL-MOV SMB Admin Share Access - C$"; \
content:"C$"; nocase; sid:1000003; rev:1;)

# ---------------------------------------------------------------
# Scenario 9 — DNS Tunnelling (T1071.004)
# ---------------------------------------------------------------
alert dns any any -> any 53 (msg:"LATERAL-MOV DNS Tunnelling - Long Query String"; \
dns.query; content:"."; distance:0; byte_test:1,>,50,0,relative; \
sid:1000004; rev:1;)

alert dns any any -> any 53 (msg:"LATERAL-MOV DNS Tunnelling - Unusual Record Type"; \
dns.query; dns_query_type:16; threshold:type threshold, \
track by_src, count 5, seconds 60; sid:1000005; rev:1;)

# ---------------------------------------------------------------
# Scenarios 6, 7 — SSH Port-Forwarding / SOCKS Tunnel (T1572, T1090)
# ---------------------------------------------------------------
alert tcp $HOME_NET any -> $HOME_NET 22 (msg:"LATERAL-MOV SSH Rapid Reconnect - Tunnel Indicator"; \
flow:to_server,established; threshold:type threshold, \
track by_src, count 3, seconds 10; sid:1000006; rev:1;)

# ---------------------------------------------------------------
# Scenario 11 — Encrypted C2 (T1573)
# ---------------------------------------------------------------
alert tls any any -> any any (msg:"LATERAL-MOV TLS Direct-IP Connection - Possible C2"; \
tls.subject; content:"CN="; nocase; tls_cert_issuer; content:"CN="; nocase; \
sid:1000007; rev:1;)

alert tls any any -> any any (msg:"LATERAL-MOV TLS Missing SNI - Possible C2"; \
tls.sni; content:!""; sid:1000008; rev:1;)

# ---------------------------------------------------------------
# Scenario 14 — LLMNR Poisoning (T1557.001)
# ---------------------------------------------------------------
alert udp any any -> 224.0.0.252 5355 (msg:"LATERAL-MOV LLMNR Response from Unexpected Host"; \
content:"|00 00 84 00|"; offset:2; depth:4; sid:1000009; rev:1;)
