# SOC Detection & Response Lab

> 🚧 **Status:** in progress, Phase 0 (foundations)

A home Security Operations Centre built on an 8 GB laptop at zero cost. It detects, triages and blocks attacks, and every detection is written as code, tested automatically and documented like production content.

## What this project demonstrates

| Skill | Where it is shown |
| --- | --- |
| Log analysis and SIEM | Wazuh with Windows, Sysmon, Linux and network logs |
| Detection engineering | Custom Sigma rules mapped to MITRE ATT&CK |
| Detection-as-Code | Rules in Git, validated and tested by GitHub Actions |
| Detection testing | Atomic Red Team in the lab, public attack datasets in CI |
| IDS/IPS | Suricata with custom rules and a documented IDS-to-IPS rollout |
| SOAR and incident response | Shuffle playbooks, TheHive cases, incident reports |
| Threat hunting | Hypothesis-driven hunts and an ATT&CK coverage gap report |

## Roadmap

- [ ] Phase 0: Foundations, threat model, repository setup
- [ ] Phase 1: Lab infrastructure (hypervisor, Active Directory, web server)
- [ ] Phase 2: Telemetry and SIEM (Sysmon, audit policy, Wazuh)
- [ ] Phase 3: Network detection with Suricata (IDS mode)
- [ ] Phase 4: Detection engineering (Sigma rules, testing harness)
- [ ] Phase 5: Detection-as-Code CI pipeline
- [ ] Phase 6: SOAR and case management
- [ ] Phase 7: Prevention (IPS and automated response)
- [ ] Phase 8: Threat hunting and adversary emulation
- [ ] Phase 9: Metrics and final write-up

## Repository structure

```
docs/            architecture, response policy, incident reports, weekly journal
detections/      sigma/ (source of truth), wazuh/, suricata/
runbooks/        one triage runbook per detection
tests/           detection test harness and results
soar/            exported Shuffle workflows
configs/         Sysmon, Wazuh, Suricata and policy configurations
coverage/        MITRE ATT&CK Navigator layers
```

## Safety note

All attack simulations run only inside an isolated lab I own, for defensive learning. No techniques here are used against systems I do not own.
