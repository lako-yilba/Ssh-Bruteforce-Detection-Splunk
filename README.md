# SSH Brute-Force Detection using Splunk SIEM

A home lab project simulating SSH brute-force attacks and detecting them 
using Splunk Enterprise. Built as part of my SOC analyst portfolio.

## What This Project Does

This lab simulates a real-world credential abuse attack where an attacker 
repeatedly tries username and password combinations to break into a Linux 
server over SSH. The goal was to detect this pattern using a SIEM before 
the attacker gets in — or catch them right after.

## Lab Environment

| Machine | Role |
|---|---|
| Kali Linux | Attacker machine |
| Ubuntu Server | Target machine (SSH enabled) |
| Splunk Enterprise | SIEM — log collection and detection |
| pfSense | Firewall logging |
| Suricata IDS | Intrusion detection |

All machines run inside VirtualBox on a Host-Only network (192.168.56.x).

## Attack Simulation

Used two tools to simulate the brute-force:

**Hydra**
```bash
hydra -l testuser -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.10 -t 4 -V
```

**Metasploit**
```
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.56.10
set USERNAME testuser
set PASS_FILE /usr/share/wordlists/rockyou.txt
set THREADS 5
run
```

Both tools generated hundreds of failed SSH login attempts recorded 
in `/var/log/auth.log` on the target machine.

## Detection Logic

Logs from Ubuntu Server's `auth.log` were forwarded to Splunk using 
the Universal Forwarder. Detection was built around three patterns:

- Any IP exceeding 10 failed logins in a 5-minute window
- Multiple usernames targeted from the same IP
- A successful login following a high number of failures (breach indicator)

## Key SPL Queries

**Threshold detection — flags any IP with over 10 failures in 5 minutes:**
```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=5m
| stats count as failures by src_ip, _time
| where failures > 10
```

**Breach indicator — detects when brute-force succeeded:**
```spl
index=main sourcetype=linux_secure ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex "(?<status>Failed|Accepted) password for (?<user>\S+)"
| stats count(eval(status="Failed")) as failures,
        count(eval(status="Accepted")) as successes by src_ip, user
| where failures > 5 AND successes > 0
```

## Splunk Dashboard

Built a real-time monitoring dashboard in Splunk Dashboard Studio with:

- Attack timeline showing failed login spikes
- Top attacking IPs ranked by failure count
- Threshold breach table
- Breach detection panel (fail then succeed pattern)
- Full failed login event table

## Alert

Configured a scheduled alert to run every 5 minutes. It triggers 
whenever any IP crosses the 10-failure threshold — designed to 
notify a SOC analyst in real time during an active attack.

## Results

Kali Linux (192.168.56.20) was detected with 11 failed SSH attempts 
in a single 5-minute window, crossing the alert threshold. The 
brute-force was successfully identified before manual review, 
demonstrating automated threat detection working as expected.

## Skills Demonstrated

- Offensive simulation (Hydra, Metasploit, Nmap)
- Linux log analysis (auth.log)
- SIEM deployment and configuration (Splunk Enterprise)
- SPL query writing for threat detection
- Dashboard creation (Splunk Dashboard Studio)
- Threshold-based alert engineering
- Multi-source log correlation (auth.log + Suricata)

## Part of Larger SIEM Lab

This project is one component of a broader SIEM home lab that 
includes pfSense firewall logging, Suricata IDS alerts, and 
Windows Event Log monitoring — all centralized in Splunk.
