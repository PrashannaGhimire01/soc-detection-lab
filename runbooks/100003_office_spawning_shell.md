# Runbook: Office App Spawning a Shell (Rule 100003)

| Field | Value |
| --- | --- |
| Rule ID | 100003 (level 12) |
| Detection | An Office app launched a command shell or script host |
| ATT&CK | T1204.002 User Execution, T1059.001 PowerShell |
| Data source | Sysmon Event 1 (process creation), ParentImage + Image |
| Threat model | Path 3 (phishing), step 2: malicious macro runs code |
| Sigma source | detections/sigma/0003_office_spawning_shell.yml |

## What fired and why it matters

A Microsoft Office application (Word, Excel, etc.) started a child process that is a
shell or script host (powershell, cmd, mshta, wscript...). Office has no legitimate
reason to do this, so it almost always means a malicious macro in a document just ran.
This is the execution step of a phishing attack and one of the highest-value detections.

## Triage: first three questions

1. **What ran, and with what command line?**
   Fields: `win.eventdata.parentImage`, `win.eventdata.image`, `win.eventdata.commandLine`.
   An encoded command (`-enc`), a download (`IEX`, `Invoke-WebRequest`, `DownloadString`),
   or a connection to an external host is a strong true-positive signal.
2. **Who and where?** Fields: `win.eventdata.user`, `agent.name`. Which staff member
   opened the document?
3. **What happened next?** Pivot on the child process: did it make a network connection
   (Sysmon 3), create files (Sysmon 11), or access LSASS (Sysmon 10)? That shows the
   attacker's follow-on actions.

## How to tell a false positive

- Rare legitimate Office add-ins or automation can shell out; if confirmed benign,
  document the specific parent/child/command line and add a narrow exception.
- True positive signs: encoded or obfuscated command line, network download, execution
  from a temp or Downloads folder, unusual user or time.

## Containment (if confirmed)

1. Isolate the workstation from the network.
2. Kill the malicious process tree.
3. Reset the user's credentials (assume stolen if credential access followed).
4. Collect the original document for analysis; warn other staff of the phishing lure.

## Escalate when

- The command line downloads or executes remote code, or
- Follow-on credential access (LSASS) or lateral movement is seen.

## Testing notes

- DC01 has no Microsoft Office installed. Simulated by copying cmd.exe to WINWORD.EXE and
  launching powershell from it, so Sysmon records ParentImage ...\WINWORD.EXE (same method
  as Atomic Red Team T1204.002). The rule matched on the fresh event.
- Rule widened beyond cmd/powershell to include mshta, regsvr32, rundll32, wscript, cscript
  (common living-off-the-land children of malicious macros).
