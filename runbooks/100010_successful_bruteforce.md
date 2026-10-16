# Runbook: Successful Brute Force (Rules 100002 -> 100010)

| Field | Value |
| --- | --- |
| Rule IDs | 100002 (brute force detected, level 12), 100010 (brute force SUCCEEDED, level 13) |
| Detection | A burst of failed logons for an account, then a successful logon for that same account |
| ATT&CK | T1110 Brute Force |
| Data source | Windows Security log, Event IDs 4625 (failed logon), 4624 (successful logon) |
| Threat model | Path 1, step 1->2: attacker guesses the password and gets a foothold on DC01 |
| Sigma source | detections/sigma/0002_successful_bruteforce.yml |

## What fired and why it matters

Rule 100002 flagged 8+ failed logons for one account in 2 minutes (a brute force). Then rule 100010
fired because a **successful logon (4624) arrived for that same account** within 10 minutes - meaning
the guessing **worked** and the attacker is now authenticated. This is the difference between
"someone is knocking" and "someone is inside." On DC01 (a domain controller) a cracked account can
mean domain-wide compromise, so 100010 (level 13) is a page-someone event.

## Rule chaining (how to read the alerts)

- 100001 fires on each failed logon (4625). Low level, mostly for correlation.
- 100002 fires when 8+ of those hit the same user in 120s = brute force in progress.
- 100010 fires when a successful logon (native rule 60106 / event 4624) then arrives for that same
  user within 10 minutes. Wazuh shows 100010 as the alert; it means the brute force succeeded.

## Triage: first three questions

1. **Which account, and from where?** Fields: `win.eventdata.targetUserName`, `win.eventdata.ipAddress`,
   `win.eventdata.logonType` on the 4624. An external/unknown source IP or an odd logon type raises severity.
2. **Is this account expected to see failed logons?** A service or admin account being brute forced
   and then "succeeding" is high-confidence malicious. A normal user may just have fat-fingered then
   logged in - check the count and timing.
3. **What did the account do after the successful logon?** Pivot on the same user/host: new processes
   (Sysmon 1), credential access (100004/100008), new accounts or group changes (100005-100007),
   lateral movement. A brute force is initial access - find the follow-on activity.

## How to tell a false positive

- Legitimate: a real user who mistyped repeatedly and then signed in, from their normal workstation,
  during working hours. The 8-failure threshold already filters most of these out.
- True positive signs: many failures, a remote/unfamiliar source IP, a privileged or service account,
  off-hours, and especially any suspicious activity immediately after the success.

## Containment (if confirmed)

1. Disable the compromised account immediately; the attacker is already authenticated as it.
2. Reset its password (and, if privileged on the DC, begin domain credential rotation).
3. Isolate any host the account logged on to from the success event onward.
4. Hunt for persistence and lateral movement performed after the successful logon.

## Escalate when (always, for 100010)

- Any 100010 is a confirmed-access event. Escalate to IR; on DC01 or any privileged account, treat
  as a critical incident.

## Testing notes

- 2026-10-16 v1: Created a throwaway domain account `bf.victim` with a known password.
- First attempt used `net use \\DC01\IPC$` for the failed logons - this produced NO 4625 events.
  Two reasons: (a) domain auth prefers Kerberos, whose failures log 4771, not 4625; (b) loopback SMB
  to the local DC plus Windows' "multiple connections to the same server" blocking meant most
  attempts never reached authentication. Lesson: the attack technique decides which event you get.
- Fixed by generating logons with the Win32 `LogonUser` API (network logon, type 3): 10 wrong
  passwords produced 10x 4625 (firing 100002), then the correct password produced a 4624 for the
  same user (firing 100010). Network logon (type 3) needs no "log on locally" right, so it works for
  a normal domain user against a DC.
- Future improvement: extend detection #1 to also cover Kerberos pre-auth failures (4771) so Kerberos
  brute forcing is caught too.
- Cleanup: remove the test account when finished - `Remove-ADUser bf.victim -Confirm:$false`.
