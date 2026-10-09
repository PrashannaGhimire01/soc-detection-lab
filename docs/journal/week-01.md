# Week 1 journal

## Phase 0 (done)
- Lessons: SOC basics, ATT&CK and Kill Chain, networking, Windows and Linux logs
- Created this repo and wrote the threat model for Himal Traders

## Phase 1 so far
- Installed VMware Workstation Pro 26H1u1 and verified the installer's SHA256 hash
- Created the host-only lab network VMnet1 = 10.10.10.0/24 (host = 10.10.10.1, DHCP off)
- Built DC01: Windows Server 2022 Standard Evaluation (Desktop Experience), VMware Tools, fully updated
- Evaluation activated: 180 days, expires around April 2027 (6 rearms available)

## Problems and fixes
- DC01 clock was on US Pacific time. Fixed with Set-TimeZone "Nepal Standard Time".
  Why it matters: wrong time zones break attack timelines when correlating logs.
- First update restart looked stuck on "Update Orchestrator Service"; it was just installing updates.

## WEB01 (Phase 1.4)
- Built Ubuntu 24.04 server WEB01, static IP 10.10.10.30 on VMnet1
- Installed Apache, MariaDB, PHP and DVWA (deliberately vulnerable, sealed network only)
- Fixed SSH: had wrong IP (.149 vs .129); DHCP address had changed. Confirms why servers need static IPs.

## Phase 1 COMPLETE (2026-10-09)
- WEB01 built: Ubuntu 24.04, Apache, MariaDB, DVWA, static 10.10.10.30
- WSL2 Ubuntu attacker installed (nmap, sqlmap, hydra); bridged networking not supported with VMware, so attacks will run from a host on the lab network instead
- Phase 1 test passed: ram.sharma account valid (Enabled, not LockedOut); normal users correctly blocked from logging into the DC (AD security rule); DC01 reaches WEB01 on ports 22 and 80
- Lesson learned: netplan static IP needed 'netplan apply' after moving WEB01 to VMnet1
