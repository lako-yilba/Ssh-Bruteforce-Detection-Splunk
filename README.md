# SSH Brute-Force Detection using Splunk SIEM

A home lab project simulating SSH brute-force attacks and detecting them using Splunk Enterprise. Built as part of my SOC analyst portfolio to practice real-world threat detection workflows.

---

## What This Lab Is For

This lab is for learning how to detect credential abuse attacks in a SIEM environment.

SSH brute-force is one of the most common attacks SOC analysts deal with — an attacker hammers a login with thousands of password guesses until one works. The evidence always ends up in `auth.log`, and this lab is about learning to read that evidence fast, at scale, using Splunk.

---

## Lab Environment

| Machine | Role |
|---|---|
| Kali Linux | Attacker |
| Ubuntu Server | Target (SSH enabled) |
| Splunk Enterprise | SIEM — log collection and detection |
| pfSense | Firewall logging |
| Suricata IDS | Network intrusion detection |

All VMs run in VirtualBox on a Host-Only network (`192.168.56.x`).

---

## Attack Tools Used

- **Nmap** — port scanning and recon
- **Hydra** — SSH password brute-force
- **Metasploit** (`ssh_login` module) — automated credential testing

---

## Detection Approach

- SSH logs forwarded from Ubuntu Server to Splunk via Universal Forwarder
- SPL queries written to identify failed login patterns in `auth.log`
- Threshold-based alert configured to fire when failures exceed limit in a 5-minute window
- Suricata network alerts correlated with SSH log data for multi-source detection

---

## Files in This Repo

| File/Folder | What's Inside |
|---|---|
| `README.md` | Project overview |
| `WALKTHROUGH.md` | Full step-by-step with screenshots |
| `screenshots/` | Evidence screenshots from the lab |

---

## Part of a Larger SIEM Lab

This project is one component of a broader home lab that includes pfSense firewall logging, Suricata IDS alerts, and Windows Event Log monitoring — all centralized into one Splunk instance.
