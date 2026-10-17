# Threat Hunting — proactive sweep of Windows logs

Where the SIEM waits for a rule to fire, **hunting goes looking**: you take raw telemetry and
proactively search it for attacker traces, assuming something slipped past the alerts. This hunt
sweeps exported Windows event logs with **Chainsaw**, applying **this repo's own Sigma rules** plus
Chainsaw's ~130 built-in detection rules.

## Method

```
DC01  --wevtutil epl-->  Security.evtx / Sysmon.evtx / Defender.evtx  (~35 MB)
      --copy-->  hunting host
      --chainsaw hunt (our Sigma + built-in rules)-->  findings (CSV, ATT&CK-tagged)
```

Reproduce with [`run-hunt.ps1`](run-hunt.ps1) (Chainsaw in `C:\chainsaw`, logs in `C:\hunt-logs`).

## Findings

Chainsaw loaded **137 rules** (our Sigma + built-ins) and processed 3 logs. Results by category:

| Category | Hits |
| --- | --- |
| `sigma.csv` — our own detection rules | 57 |
| `account_tampering.csv` | 48 |
| `antivirus.csv` (Windows Defender) | 27 |
| `login_attacks.csv` | 2 |
| `lateral_movement.csv` | 1,805 |

### Our Sigma rules resurfaced every simulated attack

The hunt proves the detections are **portable** — the same Sigma that runs in the Wazuh SIEM ran
*unchanged* as standalone hunting content:

| Our Sigma rule | Technique | Hits |
| --- | --- | --- |
| New Account Created / Added to Privileged Group | T1136 / T1098 | 48 |
| Shadow Copy / Backup Deletion | T1490 | 6 |
| Windows Multiple Failed Logons (Brute Force) | T1110.001 | 2 |
| Office Application Spawning a Shell | T1204.002 / T1059.001 | 1 |

Chainsaw's independent built-in rules corroborated: new-user / group-add events (48), Defender
credential-theft catches (27), and the brute-force bursts (2).

## The key lesson: signal vs noise

The `lateral_movement` category returned **1,805 "Network Logon" hits**. That is the single most
important thing this hunt teaches: **hunting is separating signal from noise.** Almost all of those
1,805 are benign — machine-account authentication, service logons, normal domain chatter. A hunter
does **not** chase all of them. The real skill is:

1. **Baseline** what normal looks like (which accounts, hosts and logon types are routine).
2. **Filter** the volume down to the anomalies — an unexpected account, an odd source, an unusual time.
3. **Pivot** on the few that survive into the richer telemetry (Sysmon, the SIEM).

A detection that fires 1,805 times a day is useless as an alert; as a *hunting* starting point it's
fine, because the human applies judgment the rule can't. Knowing the difference is the job.

## Takeaways

- **Detection-as-Code pays off twice.** Rules authored once (Sigma) served both the live SIEM and an
  offline hunt, with no rewriting.
- **Hunting resurfaces attacks without needing a live alert** — valuable for retrospective
  investigation and for finding gaps in alerting.
- **Volume is not value.** The hunter's contribution is triage and baselining, not running the tool.

## Notes

- 1 Sigma rule did not load into Chainsaw (the brute-force *correlation* rule / the Linux-FIM and
  Defender-service rules don't map to these Windows channels) — expected, and covered by the SIEM.
- Hayabusa is a good alternative/complement (bundled Sigma set, produces a CSV timeline); the same
  exported `.evtx` feed it directly.
