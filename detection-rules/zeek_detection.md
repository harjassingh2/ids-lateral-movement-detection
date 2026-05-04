# Custom Zeek Detection Scripts
# Project: Detecting Lateral Movement in Enterprise Networks
# See rules-explained.md for plain English explanations of each script

# ---------------------------------------------------------------
# Scenario 2 — ICMP Reconnaissance (T1018)
# ---------------------------------------------------------------
global icmp_targets: table[addr] of set[addr] &default=set();

event icmp_echo_request(c: connection, icmp: icmp_conn)
    {
    add icmp_targets[c$id$orig_h][c$id$resp_h];

    if ( |icmp_targets[c$id$orig_h]| > 10 )
        {
        NOTICE([$note=Scan::Address_Scan,
                $msg=fmt("ICMP Reconnaissance: %s contacted %d hosts",
                         c$id$orig_h, |icmp_targets[c$id$orig_h]|),
                $src=c$id$orig_h,
                $identifier=cat(c$id$orig_h)]);
        }
    }

# ---------------------------------------------------------------
# Scenario 1 — Internal Port Scan (T1595)
# ---------------------------------------------------------------
global port_scan_tracker: table[addr] of set[port] &default=set();

event connection_attempt(c: connection)
    {
    add port_scan_tracker[c$id$orig_h][c$id$resp_p];

    if ( |port_scan_tracker[c$id$orig_h]| > 20 )
        {
        NOTICE([$note=Scan::Port_Scan,
                $msg=fmt("Port Scan: %s hit %d ports",
                         c$id$orig_h, |port_scan_tracker[c$id$orig_h]|),
                $src=c$id$orig_h,
                $identifier=cat(c$id$orig_h)]);
        }
    }

# ---------------------------------------------------------------
# Scenario 9 — DNS Tunnelling (T1071.004)
# ---------------------------------------------------------------
global dns_query_count: table[addr] of count &default=0;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( |query| > 50 )
        {
        NOTICE([$note=DNS::Tunnelling_Long_Query,
                $msg=fmt("DNS Tunnelling - Long query from %s: %s",
                         c$id$orig_h, query),
                $src=c$id$orig_h,
                $identifier=cat(c$id$orig_h)]);
        }

    ++dns_query_count[c$id$orig_h];
    if ( dns_query_count[c$id$orig_h] > 100 )
        {
        NOTICE([$note=DNS::Tunnelling_High_Frequency,
                $msg=fmt("DNS Tunnelling - High frequency from %s: %d queries",
                         c$id$orig_h, dns_query_count[c$id$orig_h]),
                $src=c$id$orig_h,
                $identifier=cat(c$id$orig_h)]);
        }
    }

# ---------------------------------------------------------------
# Scenarios 6, 7 — SSH Tunnel / SOCKS Pivot (T1572, T1090)
# ---------------------------------------------------------------
event connection_state_remove(c: connection)
    {
    if ( c$id$resp_p == 22/tcp && c$duration > 300 secs
         && c$orig$size < 10000 )
        {
        NOTICE([$note=SSH::Tunnel_Indicator,
                $msg=fmt("SSH Tunnel Indicator: long session low data from %s",
                         c$id$orig_h),
                $src=c$id$orig_h,
                $identifier=cat(c$id$orig_h, c$id$resp_h)]);
        }
    }

# ---------------------------------------------------------------
# Scenario 11 — Encrypted C2 (T1573)
# ---------------------------------------------------------------
event ssl_established(c: connection)
    {
    if ( c$ssl$cert_chain_fuids == [] )
        {
        NOTICE([$note=SSL::No_Certificate,
                $msg=fmt("TLS connection with no certificate from %s to %s",
                         c$id$orig_h, c$id$resp_h),
                $src=c$id$orig_h,
                $identifier=cat(c$id$orig_h, c$id$resp_h)]);
        }

    if ( ! c$ssl?$server_name )
        {
        NOTICE([$note=SSL::No_SNI,
                $msg=fmt("TLS connection missing SNI from %s to %s",
                         c$id$orig_h, c$id$resp_h),
                $src=c$id$orig_h,
                $identifier=cat(c$id$orig_h, c$id$resp_h)]);
        }
    }

# ---------------------------------------------------------------
# Scenario 14 — LLMNR Poisoning (T1557.001)
# ---------------------------------------------------------------
event udp_reply(u: connection)
    {
    if ( u$id$resp_p == 5355/udp && u$id$orig_h !in Site::local_nets )
        {
        NOTICE([$note=LLMNR::Rogue_Response,
                $msg=fmt("LLMNR response from unexpected host: %s",
                         u$id$orig_h),
                $src=u$id$orig_h,
                $identifier=cat(u$id$orig_h)]);
        }
    }
