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
