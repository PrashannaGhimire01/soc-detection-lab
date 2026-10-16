# Runbook: Defender Blocked LSASS Credential Theft (Rules 100004 / 100008)

| Field | Value |
| --- | --- |
| Rule IDs | 100004 (Defender threat detected, level 12), 100008 (credential theft vs LSASS, level 13) |
| Detection | Microsoft Defender detected/blocked a credential-theft tool targeting LSASS |
| ATT&CK | T1003.001 OS Credential Dumping: LSASS Memory |
| Data source | Microsoft-Windows-Windows Defender/Operational, Event IDs 1116 (detected), 1117 (remediated) |
| Threat model | Path 1 step 3 / Path 3 step 4: dump LSASS on DC01 to steal AD credentials |
| Sigma source | detections/sigma/0004_defender_lsass_credential_theft.yml |
| Built-in anchor | Wazuh rule 62123 (windows_defender) |

## What fired and why it matters

Microsoft Defender detected a tool trying to read the memory of **LSASS** - the Windows process
that holds logged-on users' credential material. Dumping LSASS (Mimikatz, comsvcs MiniDump, etc.)
is the classic way an attacker turns a single foothold into **domain-wide** access, so this is one
of the highest-value things we can catch. Rule 100008 (level 13) is the critical one.

This is a **"control worked" detection**: Defender already *blocked* the attempt, so the immediate
damage was prevented. That does **not** mean "ignore it" - something on the host ran a credential
stealer, which means the host is likely already compromised at some level. Investigate why.

## Why this detection uses Defender, not Sysmon

The textbook approach is Sysmon Event 10 (ProcessAccess to lsass.exe). On this hardened host that
telemetry did not fire reliably (LSASS is protected, and the ProcessAccess hook did not produce
events for our triggers). Defender's ASR rule "Block credential stealing from lsass.exe" caught and
blocked the same attack and logged it, so we detect with the telemetry we can actually collect.
Lesson: **you detect with the telemetry you have, not the telemetry you wish you had.** A second,
independent layer recording the block is also exactly the defense-in-depth story we want.

## Triage: first three questions

1. **What was the tool and the exact command?**
   Fields: `win.eventdata.threat Name` (e.g. `HackTool:Win32/DumpLsass.H`), `win.eventdata.path`
   (holds the full command line, e.g. `rundll32 ... comsvcs.dll MiniDump <lsass_pid> ...`).
2. **Who/what launched it, and as whom?** Fields: `win.eventdata.detection User`, `agent.name`.
   A SYSTEM-context launch means the attacker already had admin on the host.
3. **How did they get there?** Pivot on the same host/time: a preceding 4625 brute force (100002),
   Office-spawned shell (100003), new admin (100005-100007), or remote logon (4624 type 3/10).
   LSASS dumping is a *mid-chain* action - find the initial access that came before it.

## How to tell a false positive

- Authorized red-team / security testing. Should be pre-announced with a change ticket; confirm with
  the tester, document, and close.
- True positive signs (almost always): a known credential-dump signature name, a `comsvcs MiniDump`
  / `rundll32` / `procdump lsass` command line in `path`, an unexpected user or odd hour.

## Containment (if confirmed)

1. **Isolate the host** (DC01 especially) from the network immediately.
2. Assume credential compromise: this is a **domain controller**, so treat all domain credentials as
   potentially exposed. Begin domain-wide credential rotation (krbtgt twice, privileged accounts).
3. Hunt for what ran before and after (initial access, persistence, lateral movement).
4. Preserve the Defender detection and related events for IR; do not just dismiss the toast.

## Escalate when (always, for 100008)

- Any 100008 on DC01 is a **critical, page-someone incident** - credential theft against the domain's
  crown jewel. Escalate to IR lead / management immediately.

## Testing notes

- 2026-10-16 v1: Onboarded the Defender Operational channel into the Wazuh agent (`<localfile>` in
  `C:\Program Files (x86)\ossec-agent\ossec.conf`), restarted the agent, confirmed the subscription
  (`(1951): Analyzing event log`). Triggered with
  `rundll32 C:\Windows\System32\comsvcs.dll, MiniDump 676 C:\Windows\Temp\x.dmp full`
  (lsass PID 676). Defender blocked it ("Access is denied" + "Threats found" toast) and logged
  Event 1116/1117 with threat name `HackTool:Win32/DumpLsass.H`. Wazuh matched built-in 62123;
  rules 100004 (base) and 100008 (credential escalation) matched on the fresh event.
- Rule 100008 matches the raw event with pcre2 (`Lsass|Mimikatz|WDigest|...`) rather than the
  `win.eventdata.threat Name` field, because that decoded field name contains a space; matching the
  event body is more robust and still precise for credential tooling.
