# Intrusion Prevention (IPS) — Suricata inline on WEB01

Turns the Suricata **IDS** on WEB01 into an **IPS**: instead of only alerting on malicious web
traffic, Suricata now sits inline and **drops** it before it reaches the application. This completes
the IDS→IPS story for the lab.

## IDS vs IPS (the core trade-off)

| | IDS (before) | IPS (now) |
| --- | --- | --- |
| Position | Out-of-band, watches a copy of traffic | Inline, in the traffic path |
| Action | Alert only | Alert **and drop** |
| Risk | None to traffic | A false positive = an outage; adds latency |
| Mode here | Suricata af-packet on `ens33` | Suricata nfqueue (`-q 0`) |

Because IPS is in the critical path, you block only **high-confidence** signatures and alert (not
drop) on the rest. Here we drop two clear SQL-injection signatures and keep everything else alerting.

## How it works

```
Attacker ──HTTP:80──▶ [iptables NFQUEUE 0] ──▶ Suricata (inspect) ──drop malicious──▶ DVWA
          SSH:22 ──────────────────────────────────────────────────────────────────▶ (never queued, always safe)
```

1. **Suricata runs in nfqueue mode.** A systemd drop-in (`suricata-nfqueue.conf`) overrides the
   stock service (which launched with `--af-packet`) to launch with `-q 0` instead.
2. **iptables routes only port 80 into the queue** (`setup-ips-iptables.sh`). SSH (22) and all other
   traffic are never queued, so the box can't be locked out. `--queue-bypass` means that if Suricata
   stops, traffic flows normally instead of being dropped — a failsafe.
3. **The SQLi rules use the `drop` action** (`local.rules`). In nfqueue mode, `drop` issues NF_DROP
   to the kernel, so the malicious request never reaches Apache.

## Files

| File | Deploy to (WEB01) |
| --- | --- |
| `suricata-nfqueue.conf` | `/etc/systemd/system/suricata.service.d/` then `daemon-reload` + restart |
| `setup-ips-iptables.sh` | run once (adds the port-80 NFQUEUE rules) |
| `local.rules` | the two hardened `drop` SQLi rules (append to `/var/lib/suricata/rules/local.rules`) |

## Verification (proven)

From an attacker, same server, same moment:

| Request | Result |
| --- | --- |
| `GET /` (normal) | `HTTP 200` in ~0.005 s — **allowed** |
| `GET /?q=' OR 1=1` (SQLi) | connection **times out** — **dropped** |
| `GET /?q=1 UNION SELECT ...` (SQLi) | connection **times out** — **dropped** |

That difference — legit traffic passes, the attack is silently blocked before the app sees it — is
prevention, not just detection.

## Key lessons learned

- **The stock Suricata service ignored `LISTENMODE=nfqueue` in `/etc/default/suricata`** and launched
  with `--af-packet` (IDS mode), so nothing consumed the queue and dropped packets just bypassed.
  Fixed with a systemd drop-in that forces `-q 0`. Lesson: verify the *actual* `ExecStart`, not the
  config file you *think* it reads.
- **URL-encoding evasion.** The first `OR 1=1` rule used `pcre:"...\s*OR\s*..."`, which expects
  literal whitespace. An attacker sending `%27%20OR%201=1` (URL-encoded) slipped straight past it.
  Hardened the signature to accept whitespace **or** `%20` **or** `+` as separators (rev 2). Lesson:
  signatures must account for encoded payloads or they're trivially evaded.
- **Fail-open vs fail-closed.** `--queue-bypass` makes the IPS fail *open* (traffic flows if Suricata
  dies) — safer for availability in a lab. A high-security deployment might fail *closed* instead.

## Safety / rollback

- Only port 80 is queued; SSH is never affected.
- Instant disable: `sudo iptables -F` (traffic flows normally again).
- iptables rules are made persistent via a oneshot systemd unit (`iptables-restore.service`); a
  reboot restores them, and Suricata returns inline automatically.
