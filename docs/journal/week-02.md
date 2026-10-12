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
