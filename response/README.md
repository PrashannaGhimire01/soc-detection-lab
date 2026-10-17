# Automated Response (SOAR) — Disable Compromised Account

Wazuh **Active Response** that automatically disables an Active Directory account the moment the
SIEM detects that account has been successfully brute-forced (rule **100010**). This closes the loop
from *detect* to *respond*: the attacker guesses the password and logs in → the account is disabled
before they can use it.

## Components

| File | Role |
| --- | --- |
| `active-response/disable-account.ps1` | The response logic. Reads the Wazuh alert (JSON on stdin), extracts the targeted user, refuses protected/machine accounts, and disables the rest. Deploy to `C:\Program Files (x86)\ossec-agent\active-response\bin\` on DC01. |
| `active-response/disable-account.cmd` | Windows wrapper Wazuh invokes; pipes the alert into PowerShell. Same folder. |
| `wazuh-ar-config.xml` | The manager-side config (`<command>` + `<active-response>`) added to SIEM01's `ossec.conf`. |

## How it works

```
Attacker brute-forces bf.victim ──▶ 8+ failed logons (4625) ──▶ rule 100002 (brute force)
        ──▶ successful logon (4624) ──▶ rule 100010 (brute force SUCCEEDED, level 13)
        ──▶ Wazuh Active Response ──▶ disable-account.cmd on DC01 ──▶ Disable-ADAccount bf.victim
```

## Safety design (important)

Automated response that disables accounts is powerful and can cause self-inflicted outages, so the
script is built defensively:

- **Protected-account allowlist** — never disables `Administrator`, `krbtgt`, `guest`,
  `defaultaccount`, or any machine account (names ending in `$`).
- **Idempotent** — if the account is already disabled, it does nothing.
- **Fully logged** — every decision (disabled / refused / error) is written to
  `active-response/disable-account-ar.log` with a timestamp.

In production you would additionally gate this behind an approval workflow for non-critical alerts;
here the allowlist + high-confidence trigger (a *successful* brute force) is the safeguard.

## Verification status

- **Response script — verified.** Fed a sample 100010 alert, it disabled `bf.victim`
  (`Enabled: False`) and correctly **refused** to disable `Administrator` (allowlist works).
- **Detection — verified.** Rule 100010 fires reliably on the simulated attack.
- **Manager wiring — configured.** `<command>`/`<active-response>` present in `ossec.conf`;
  `disable-ad-account` registered in the generated `ar.conf` and synced to the agent.
- **Fully-automatic end-to-end trigger — known open issue.** The detection fires and the command is
  registered on both manager (`ar.conf`) and agent, but `wazuh-execd` on the agent never receives
  the command when rule 100010 fires, so the account is not auto-disabled. Troubleshooting performed:
  verified the command reaches `ar.conf` and syncs to the agent; ruled out the AR whitelist (loopback
  only); fixed a real config bug where the `<command>`/`<active-response>` blocks had landed in a
  second `<ossec_config>` section instead of the main one (consolidated into one block); switched
  `<location>` from `local` to `defined-agent`; and confirmed on a fresh, healthy, clean-timed run
  that the response still does not dispatch. Current hypothesis: a Wazuh active-response routing quirk
  for alerts produced by a composite correlation rule (`if_matched_sid`) targeting a Windows agent.
  Next avenues to try: a non-correlation test rule to isolate whether any AR dispatches to this agent;
  a manager-side (`<location>server</location>`) response using the Wazuh API to disable the account;
  or raising it with the Wazuh community. The response script and detection are independently verified
  (below), so the capability is built; only the automated hand-off remains.

## Clean re-test procedure (run on a rested lab)

1. Reboot SIEM01 and DC01; confirm both are healthy (`Get-ADUser` works on DC01; manager `active`).
2. Leave the lab idle ~5 minutes (clears the 100002/100010 correlation windows).
3. On DC01, enable `bf.victim`, run the brute-force-then-success simulation once (`LogonUser` API,
   10 wrong passwords then the correct one).
4. Wait ~40 s, then check: `Get-ADUser bf.victim` should be `Enabled: False`, and
   `active-response\active-responses.log` should show a fresh `disable-account.cmd` entry.
