# Runbook: Windows Brute Force (Rule 100002)

| Field | Value |
| --- | --- |
| Rule IDs | 100001 (base, level 3), 100002 (correlation, level 12) |
| Detection | 8+ Windows failed logons (4625) for the same user within 2 minutes |
| ATT&CK | T1110.001 Brute Force: Password Guessing |
| Data source | Windows Security log, Event ID 4625 |
| Threat model | Path 1 (ransomware via RDP), step 1 |
| Sigma source | detections/sigma/0001_windows_bruteforce_failed_logons.yml |

## What fired and why it matters

A single account received many failed logons in a short window. This is the classic
sign of password guessing. In the Himal Traders threat model it is the entry point
of the highest-ranked attack path, so catching it early buys the most response time.

## Triage: first three questions

1. **Which account and which host?** Fields: `win.eventdata.targetUserName`, `agent.name`.
   A privileged account (e.g. hari.admin, Administrator) or the domain controller (DC01)
   raises severity.
2. **Where from?** Field: `win.eventdata.ipAddress` and `win.eventdata.logonType`.
   LogonType 10 = RDP (remote). An external or unknown internal IP is more suspicious
   than a known workstation. A blank IP usually means a local attempt.
3. **What happened next?** Search for a **4624 (success)** for the same user right after
   the failures. Failures followed by a success = likely compromise, escalate immediately.

## How to tell a false positive

- A real user who forgot their password: usually a handful of failures, then they
  succeed or stop, from their own workstation, during working hours.
- A service account with a stale cached password: repeats on a schedule, same host,
  no interactive logon.
- True positive signs: many accounts targeted, odd hours, unknown source IP, RDP logon
  type, or a success immediately after the burst.

## Containment (if confirmed)

1. Disable the targeted account and end its sessions.
2. Block the source IP (network IPS / host firewall).
3. If a 4624 success followed, treat the account as compromised: reset its password,
   check for new accounts (4720) and group changes (4728/4732).

## Escalate when

- A successful logon (4624) followed the failures, or
- The target is a privileged account or DC01, or
- The source is external / unrecognised.

## Tuning history

- 2026-10-14 v1: initial rule grouped by source IP (`same_source_ip`). A local
  PowerShell credential test produced events with no source IP, so 100002 did not
  fire (base rule 100001 did). Changed grouping to the targeted username
  (`same_field win.eventdata.targetUserName`) so the rule catches both local and
  network credential attacks. Re-tested: 100002 fires correctly.
