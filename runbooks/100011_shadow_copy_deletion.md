# Runbook: Shadow Copy / Backup Deletion (Rule 100011)

| Field | Value |
| --- | --- |
| Rule ID | 100011 (level 14) |
| Detection | A command deleted shadow copies / backups or disabled Windows recovery |
| ATT&CK | T1490 Inhibit System Recovery |
| Data source | Sysmon Event 1 (process creation), field win.eventdata.commandLine |
| Threat model | Path 1, final step: ransomware destroys backups before encrypting |
| Sigma source | detections/sigma/0007_shadow_copy_deletion.yml |

## What fired and why it matters

Something ran a command that destroys the system's ability to recover - deleting Volume Shadow
Copies, deleting backups, or disabling Windows recovery. Ransomware does this **immediately before
encrypting** so victims can't just restore their files. This is one of the highest-urgency alerts in
the environment: it fires in the narrow window between the attacker having control and the files
being locked. Treat it as **ransomware in progress until proven otherwise** - minutes matter.

## Triage: first three questions (move fast)

1. **What exact command, and who ran it?** Fields: `win.eventdata.commandLine`, `win.eventdata.image`,
   `win.eventdata.parentImage`, `win.eventdata.user`. A shell or Office app as the parent is a huge
   red flag; a known backup product is the main benign case.
2. **Is this host already compromised?** Pivot on the same host for earlier stages: brute force
   (100002/100010), Office-spawned shell (100003), credential theft (100004/100008), new admin
   (100005-100007). Shadow deletion is late-stage - the initial access happened before it.
3. **Is encryption already happening?** Look for mass file modification/rename, unusual process CPU,
   ransom notes being written. If yes, this is a live ransomware incident.

## How to tell a false positive

- Legitimate: backup/imaging software managing shadow storage, or an admin doing maintenance with a
  change ticket, from an expected parent process during working hours.
- True positive signs: `/all /quiet`, run by a non-backup process (cmd, powershell, an Office child,
  a random binary), off-hours, on a machine with no backup role, or alongside any earlier-stage alert.

## Containment (if not clearly benign - act first, confirm later)

1. **Isolate the host from the network immediately** to stop encryption spreading to shares.
2. Kill the offending process tree.
3. Preserve volatile evidence if feasible, but containment comes first.
4. Identify and protect backups that are offline/immutable; do not reconnect the host to them.
5. Begin ransomware IR: scope other hosts, rotate credentials (this is DC01 - assume domain exposure).

## Escalate when (essentially always)

- Any 100011 that isn't immediately tied to known backup software is a **critical, page-on-call**
  event. On DC01, treat as a domain-wide ransomware incident until disproven.

## Testing notes

- 2026-10-16 v1: Triggered with `vssadmin delete shadows /all /quiet` on DC01. Defender did NOT block
  it (it ran, returning "No items found"), and Sysmon logged Event 1.
- First version of the rule did not fire. Root cause: the regex anchored on `vssadmin(\.exe)?\s+delete`,
  but the real command line was `"C:\Windows\system32\vssadmin.exe" delete shadows ...` - the closing
  quote after `vssadmin.exe` sits where the regex expected whitespace, so it never matched. Fixed by
  matching the behavioral phrase (`delete shadows`, etc.) anywhere in the command line instead of
  anchoring to the binary/argument spacing. Lesson: match on behavior, not on exact command formatting.
- Future improvement: also alert on Windows Event 524 (backup catalog deleted) and ESENT/VSS service
  events for defense in depth, in case the process-creation telemetry is evaded.
