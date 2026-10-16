# Runbook: Web Shell Dropped in Web Root (Rule 100012)

| Field | Value |
| --- | --- |
| Rule ID | 100012 (level 12) |
| Detection | A PHP script was created/modified in the web root on WEB01 |
| ATT&CK | T1505.003 Server Software Component: Web Shell |
| Data source | File Integrity Monitoring (FIM / syscheck), realtime on /var/www/html |
| Threat model | Path 2: public web server (DVWA) compromised, attacker plants a web shell |
| Sigma source | detections/sigma/0006_webshell_dropped.yml |
| Built-in anchor | Wazuh rules 554 (file added) / 550 (file modified) |

## What fired and why it matters

A new or modified server-side script appeared in the web directory. Legitimate PHP files don't
show up there during normal running, so this is almost always a **web shell** - a small script the
attacker uploads after exploiting the web app, giving them remote command execution on the server
(e.g. `shell.php?cmd=whoami`). It is the pivot point from "web app bug" to "attacker has a foothold
on the server," so it's high severity.

## Triage: first three questions

1. **Which file, and what's in it?** Field: `file` (the path). Read the file on WEB01
   (`cat <path>`). Web shells contain `system()`, `exec()`, `passthru()`, `eval()`, `shell_exec()`,
   `base64_decode(...)`, or `$_GET`/`$_POST`/`$_REQUEST` passed into execution. A short obfuscated
   file in an uploads directory is a near-certain true positive.
2. **How did it get there?** Correlate the web access logs (`/var/log/apache2/access.log`) around
   the file's creation time for the upload request and for follow-up `?cmd=` requests. The source
   IP there is the attacker.
3. **Was it used?** Look for requests to that file returning 200, and for the web server user
   (www-data) spawning shells/recon commands afterward. That tells you if they've run commands.

## How to tell a false positive

- Legitimate: a deployment or CMS update that writes PHP files, from a known process during a
  planned change window. Document and allowlist that path/process.
- True positive signs: file in an uploads/writable directory, obfuscated or very short, contains
  command-execution functions, created right after a suspicious web request, unknown source IP.

## Containment (if confirmed)

1. Remove or quarantine the web shell file (preserve a copy for evidence first).
2. Block the attacker's source IP at the firewall / web server.
3. Isolate WEB01 if command execution is confirmed; assume the host is compromised.
4. Find and fix the upload/injection flaw that allowed it (in DVWA's case, the file-upload vuln).
5. Hunt for additional shells, modified pages, and persistence; review what the shell accessed.

## Escalate when

- The file contains command-execution code, OR there is evidence it was accessed/used, OR
  www-data is seen spawning shells after it appeared.

## Testing notes

- 2026-10-16 v1: Enabled FIM in WEB01's agent ossec.conf - added
  `<directories realtime="yes" check_all="yes" report_changes="yes">/var/www/html</directories>`
  and `<alert_new_files>yes</alert_new_files>` (Wazuh does not alert on brand-new files by default),
  restarted the agent.
- WEB01 was not actually enrolled with the manager (running agent != connected agent). Fixed with
  `agent-auth -m 10.10.10.10`; it then appeared Active as agent 003. The manager (SIEM01) correctly
  does not appear in the agent list - it is the manager, not an agent.
- Triggered by writing `shell.php` to the web root. The test payload is a one-line PHP web shell
  of the form: open tag, then `sys`+`tem(...)` called on a value read from a `$_GET` request
  parameter, then close tag. (Written split like this on purpose so antivirus does not flag this
  document on download.) Native rule 554 fired at level 5; rule 100012 elevates PHP writes to level 12.
- Rule-writing gotchas learned: the FIM path is `syscheck.path` in the alert JSON but must be matched
  as `<field name="file">` in a rule; and rule changes only apply to events generated AFTER the
  manager restart (deploy first, then trigger).
- Future improvement: add content inspection (CDB list / regex on the file body for web-shell
  signatures) and an auditd rule for the web server user (www-data) spawning shells - that catches
  command execution even if the shell is written somewhere FIM isn't watching.
