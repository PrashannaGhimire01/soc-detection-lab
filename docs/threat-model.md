# Threat Model: Himal Traders Pvt. Ltd.

> Purpose: decide what the SOC protects, from whom, and which detections to build first.
> Version 1.0, Phase 0. Reviewed again after Phase 8 (threat hunting).

## 1. Company summary

Himal Traders Pvt. Ltd. is a 25-person trading company in Kathmandu. Staff use a Windows domain (`lab.local`, DC01). Customers order through a web app on WEB01 (Ubuntu Linux). Remote work uses RDP. Passwords are weak and there is no multi-factor authentication.

## 2. Assets (what is valuable?)

| Asset | Where it lives | Why it matters | Value |
| --- | --- | --- | --- |
| Active Directory (all staff accounts) | DC01 | Whoever controls it controls every computer and account | High |
| Customer data (names, phone numbers, addresses, order history, payment status) | Web app database on WEB01 | A leak harms customers, breaks trust, and can bring legal trouble under Nepal's Individual Privacy Act; stolen data can be sold or used for fraud. Card details are not stored; a payment provider handles them | High |
| Finance invoices | Finance file share on DC01 | Needed for tax (IRD) records and paying suppliers; if altered, money can be sent to an attacker's account (invoice fraud); if encrypted, billing stops | High |
| The web app itself (taking orders) | WEB01 (internet-facing) | The main way the company earns money; if it is down or defaced, orders stop and customers go elsewhere. It is also a door into the network | High |

## 3. Threat actors (who might attack us?)

| Threat actor | What they want | How skilled | Likelihood |
| --- | --- | --- | --- |
| Ransomware gang | Money: encrypt files and demand payment | Medium to high | High |
| Opportunistic web attacker | Steal customer data to sell, deface the site, plant a cryptominer, or use WEB01 as a foothold | Low to medium (automated scanners and public exploits) | High |
| Insider (unhappy employee) | Revenge or profit: copy customer lists for a competitor, delete data, or commit invoice fraud | Low to medium, but already has valid access and knows where data is | Medium |

## 4. Attack surface (where can they get in?)

- RDP open for remote work, protected only by weak passwords
- The web app on WEB01: login page, search and order forms, and any file upload, all reachable from the internet (SQL injection, weak admin password, unpatched software)
- Email (phishing): fake invoices or "order" emails with malicious attachments, or links that steal passwords
- Staff accounts: weak, possibly reused passwords with no MFA, so any leaked or guessed password works everywhere (also how an ex-employee gets back in if accounts are not disabled)

## 5. Likely attack paths

**Path 1: Ransomware through RDP**
1. Attacker brute-forces an RDP password (Credential Access, T1110)
2. Logs in with the stolen account (Initial Access, T1078)
3. Dumps more passwords from LSASS (Credential Access, T1003.001)
4. Creates a backdoor admin account (Persistence, T1136)
5. Deletes shadow copies so files cannot be restored (Impact, T1490)
6. Encrypts files on DC01 (Impact, T1486)

**Path 2: Web attack on WEB01**
1. Attacker scans WEB01 for weak spots (Reconnaissance, T1595.002 Vulnerability Scanning)
2. Exploits SQL injection in the order or search form (Initial Access, T1190 Exploit Public-Facing Application)
3. Uploads a web shell to keep access (Persistence, T1505.003)
4. Runs Linux commands on WEB01 through the web shell (Execution, T1059.004 Unix Shell)
5. Dumps the customer database and sends it out (Collection, T1005; Exfiltration, T1041)

**Path 3: Phishing email**
1. Staff member gets a fake supplier invoice with a malicious Word attachment (Initial Access, T1566.001)
2. User opens it and enables macros, which runs PowerShell (Execution, T1204.002 and T1059.001)
3. Malware calls back to the attacker over HTTPS (Command and Control, T1071.001)
4. Attacker dumps credentials and moves to DC01 with RDP or SMB (Credential Access, T1003.001; Lateral Movement, T1021.001 / T1021.002)
5. Deletes shadow copies, steals finance invoices and deploys ransomware (Impact, T1490; Exfiltration, T1041; Impact, T1486)

## 6. Risk ranking

Scale: Low = 1, Medium = 2, High = 3. Risk = Likelihood x Impact.

| Rank | Attack path | Likelihood | Impact | Why this rank |
| --- | --- | --- | --- | --- |
| 1 | Path 1: Ransomware through RDP | High (3) | High (3) | Score 9. RDP is exposed, passwords are weak, no MFA, and bots scan for RDP all day. No user has to click anything, and it leads straight to DC01, which stops the whole company. |
| 2 | Path 3: Phishing email | High (3) | High (3) | Score 9. Phishing is the most common attack on small companies and ends in the same place (DC01, ransomware). Ranked just below Path 1 because it needs a user to click and has more steps, which gives us more chances to detect it. |
| 3 | Path 2: Web attack on WEB01 | Medium (2) | High (3) | Score 6. WEB01 is always being scanned, but the attack only works if the app has a real flaw. Impact is high (customer data leak, lost orders), but WEB01 is one server, not the whole domain. |

## 7. Detection priorities

| Priority | Detection | Data source | ATT&CK | Attack path it catches |
| --- | --- | --- | --- | --- |
| 1 | Brute force on RDP or SSH (many failures from one source) | 4625; auth.log | T1110.001 | Path 1, step 1 |
| 2 | Successful logon after many failures (4625 burst, then 4624 logon type 10) | 4625, 4624 | T1110 / T1078 | Path 1, step 2 |
| 3 | Office app spawning PowerShell or cmd (WINWORD.EXE / EXCEL.EXE parent) | Sysmon 1 | T1204.002 / T1059.001 | Path 3, step 2 |
| 4 | LSASS memory access by a non-system process | Sysmon 10 | T1003.001 | Path 1, step 3; Path 3, step 4 |
| 5 | New user created or added to Domain Admins / Administrators | 4720, 4728, 4732 | T1136 / T1098 | Path 1, step 4 |
| 6 | Web server user spawning a shell (www-data running sh or bash, parent nginx, apache2 or php-fpm) | auditd (execve) | T1505.003 / T1059.004 | Path 2, steps 3–4 |
| 7 | Shadow copy deletion (vssadmin delete shadows, wmic shadowcopy delete) | Sysmon 1, 4688 | T1490 | Path 1, step 5; Path 3, step 5 (early ransomware warning) |
| 8 | Mass file renames or ransom note creation (many writes with a new extension) | Sysmon 11 | T1486 | Path 1, step 6; Path 3, step 5 (last line of defence) |

Priorities 1–3 fire at the start of the two highest-ranked paths, so they buy the most time to respond. 4 and 5 catch both paths before the damage stage. 6 covers the web path. 7 warns that ransomware is about to start, and 8 is a late but high-confidence alarm.

## 8. Assumptions and limits

- The lab has one domain controller (DC01, also acting as the Windows victim), one web server (WEB01, Ubuntu), and no real users.
- Windows Security logs, PowerShell logs and Sysmon are forwarded from DC01. WEB01 forwards auth.log, web access logs and auditd. Without Sysmon, detections 3, 4, 7 and 8 do not work; without auditd, detection 6 does not work.
- No real email gateway exists in the lab, so the phishing path is simulated by running the attachment directly on DC01; detection starts at execution, not delivery.
- Multi-host lateral movement is limited with one Windows machine; it is tested with public attack datasets instead.
- Insider threat detection (unusual data access by valid users) is out of scope for version 1.0 and is a candidate for a later version.
- Backups, patch levels and endpoint protection (EDR or antivirus) are not modelled; in a real company these would change the impact scores a lot.
