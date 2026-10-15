# Runbook: New Account / Privileged Group Change (Rules 100005-100007)

| Field | Value |
| --- | --- |
| Rule IDs | 100005 (new user, level 8), 100006 (group add, level 8), 100007 (privileged group add, level 13) |
| Detection | New account created, or account added to a privileged group |
| ATT&CK | T1136 Create Account, T1098 Account Manipulation |
| Data source | Windows Security log, Event IDs 4720, 4728, 4732, 4756 |
| Threat model | Path 1 (ransomware via RDP), step 4: backdoor admin account |
| Sigma source | detections/sigma/0005_windows_new_account_privileged.yml |

## What fired and why it matters

An attacker who has admin access often creates a new account and adds it to a
privileged group (Domain Admins, Administrators). This gives them a durable way back
in even if the original stolen password is reset. Rule 100007 (level 13) is the
critical one: someone just gained domain-level power.

## Rule chaining (how to read the alerts)

- 100005 fires on a new account creation (4720).
- 100006 fires when an account is added to any group.
- 100007 escalates 100006 when the group is privileged. Wazuh shows the final rule
  in the chain, so a privileged add appears as 100007, not a separate 100006.

## Triage: first three questions

1. **Who was created / added, and to what group?**
   Fields: `win.eventdata.targetUserName` (group for 4732/4728), `win.eventdata.memberSid` (the account).
2. **Who did it?** Field: `win.eventdata.subjectUserName`. Is that account expected to
   manage privileged groups? Was there a change ticket?
3. **Where from?** Account-change events have NO source IP. Correlate with the 4624
   (logon type 3) event for the same subject/time; its `win.eventdata.ipAddress` is the
   source. A remote/unknown IP raises severity.

## How to tell a false positive

- Legitimate: IT onboarding staff or granting admin during working hours, from a known
  admin account, with a matching change request.
- True positive signs: an unfamiliar account name (backup, support, svc-xxx), odd hours,
  a remote source IP on the correlated 4624, or no change ticket.

## Containment (if confirmed)

1. Disable and remove the new/added account from the privileged group.
2. Reset the subject account's password (it may be compromised).
3. Review other recent 4720/4728/4732 events for more backdoors.
4. Hunt for what the account did next (logons, process creation).

## Escalate when

- The group is Domain Admins / Enterprise Admins / Schema Admins (domain takeover), or
- The subject account or source IP is unexpected.

## Tuning history

- 2026-10-15 v1: rule 100006 first anchored on `if_sid 60109` (the parent of 4720) and
  did not fire for group-change events (4732), which are caught by rule 60154. Inspected
  a real 4732 event, found `rule.groups` included `win_group_changed`, and re-anchored
  100006 on `<if_group>win_group_changed</if_group>`. Confirmed 100006/100007 fire on a
  fresh event. Note: Wazuh applies rules only to new events, so testing requires
  generating the event AFTER the rule reload.
