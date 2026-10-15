## Phase 2.2 COMPLETE (2026-10-12)
- DC01 Wazuh agent Active in dashboard; Sysmon logging enabled
- Verified end-to-end: test 4625 failed login appeared, auto-mapped to ATT&CK Account Access
- Observation: ~450 alerts in first minutes, nearly all benign noise. Shows why tuning/detection engineering matters.
## Phase 2.3 COMPLETE (2026-10-12)
- Enabled command-line in 4688, PowerShell script block logging (4104), advanced audit policy incl. Kerberos service tickets
- Wazuh collecting PowerShell Operational channel: 10x 4104 events confirmed in Threat Hunting
- Lesson: a leftover 'Authentication failure' filter caused a false 'No results'. Always check filters + time range first.
## Phase 2.4: WEB01 connected
- Wazuh agent active on WEB01; reads auth.log + Apache access/error logs
- auditd deferred (sealed network, no internet); will stage packages in Phase 4
- Verified: WEB01 Active in dashboard; failed SSH logins visible
## Phase 2 COMPLETE (2026-10-12)
- Both agents (DC01, WEB01) reporting to Wazuh
- Practised event triage: read rule 5710 (non-existent SSH user) and 5503 (PAM login failed), identified srcip 10.10.10.1 (my laptop) as the source
- SOC now covers Windows (Security, Sysmon, PowerShell) and Linux (auth.log, Apache)
## Phase 3.1 COMPLETE (2026-10-13)
- Suricata IDS live on WEB01, HOME_NET 10.10.10.0/24, ET Open + 2 custom rules
- Custom rule sid:1000001 (ICMP) verified firing end-to-end into Wazuh
- Fixed: custom rules must live in /var/lib/suricata/rules (default-rule-path), not /etc/suricata/rules
- Recovered a deleted netplan file with find + recreate; auditd rules loaded
## Phase 3.3: SQL injection detection (2026-10-13)
- Attacked DVWA with ' OR '1'='1 and UNION SELECT payloads (ATT&CK T1190, threat-model Path 2)
- Suricata ET Open rules detected the SQLi in HTTP from 10.10.10.1; visible in Wazuh under rule.groups:suricata
- Key concept: Suricata reads unencrypted HTTP so it sees the payload; HTTPS would hide it

## Phase 4, detection #5 COMPLETE (2026-10-15)
- New account / privileged group detection (T1136/T1098), rules 100005/100006/100007
- Attacked remotely from laptop via PSRemoting (T1021.006) - realistic lateral movement
- Debugged: 100006 wrong parent (60109 vs real 60154); re-anchored on if_group win_group_changed
- Learned: Wazuh rules apply only to NEW events; rule chaining shows the final escalated rule; account-change events have no IP (correlate with 4624)
