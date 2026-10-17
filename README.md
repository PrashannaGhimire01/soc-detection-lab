# CyberSaathi 🛡️

**An AI-assisted, offline-first, bilingual personal cybersecurity companion for
non-technical users in Nepal.**

CyberSaathi helps ordinary people — a shopkeeper, a parent, a first-time
smartphone user — stay safe online in their own language. Paste or *speak* a
suspicious message and get a plain-language risk verdict in Nepali or English;
learn through short lessons; and, on a home network, have a small gateway watch
for scams and attacks in the background.

Final-year university project (solo). Built incrementally, version by version.

---

## The four pillars

- **Protect** — detect scam messages, malicious links, and network threats.
- **Explain** — plain-language, bilingual reasons and actions ("why" + "what to do").
- **Educate** — short lessons and quizzes that build safe habits.
- **Include** — offline-first, Nepali + Romanized Nepali, voice for low literacy,
  works on low-end phones and poor connectivity.

## Research questions

- **RQ1** — Do AI-style plain-language explanations improve understanding?
- **RQ2** — Can lightweight models detect Nepali scams accurately?
- **RQ3** — Can protection work offline / in the background?
- **RQ4** — Does in-app education reduce unsafe behaviour?

---

## Version roadmap (all implemented)

| Ver | Title | What it delivers |
|-----|-------|------------------|
| v0.1 | Rule-based checker (web) | Paste a message → risk score, reasons, bilingual guidance. Rules as JSON. |
| v0.2 | ML baseline | TF-IDF + Logistic Regression on a collected dataset; honest held-out evaluation vs rules. |
| v0.3 | Android app | Share-to-CyberSaathi, results screen, lessons. |
| v0.4 | Offline | Rules + model run on the phone (local engine), bilingual parity. |
| v0.5 | Network discovery | Nmap scan → device list → plain-language, severity-ranked findings in the app. |
| v0.6 | Gateway | Kali as a home gateway: routing, DNS scam-filtering, Suricata IDS, alerts to the app. |
| v0.7 | Education + research | Lesson/quiz system, transformer-vs-TF-IDF comparison, evaluation study design. |
| v0.8 | Voice | Nepali speech-to-text input and text-to-speech output on-device. |

---

## Architecture

```
  Phone (Flutter app, offline-capable)
    ├─ Message / Link analyzer  ── online → FastAPI backend (ML + rules)
    │                           └─ offline → on-device rule engine
    ├─ Voice in/out (ne-NP / en-US)
    ├─ Emergency ("I clicked") guidance
    ├─ Learn (lessons + quizzes)
    ├─ My Network (device scan findings)
    └─ Alerts (gateway threat warnings)

  Backend (FastAPI on Render)
    /analyze/message  /analyze/url  /emergency  /lessons
    /network/scan  /network/latest  /alerts/scan  /alerts/latest

  Home gateway (Kali VM)
    routing + NAT · dnsmasq DNS filtering · Suricata IDS
    netscan/ scripts → push scan + alert reports to the backend
```

**Design principle — "rules as data":** detection logic lives in JSON
(`message_rules.json`, `url_rules.json`, `network_rules.json`, `alert_rules.json`,
`explanations.json`, `lessons.json`, `emergency.json`), loaded by both the server
and the phone so online and offline behaviour match and stay auditable.

---

## Key results (honest)

- **ML (RQ2):** TF-IDF + Logistic Regression, honest held-out evaluation with a
  leakage guard (drop train rows ≥0.80 cosine-similar to test): **~95.6%
  accuracy, scam recall ~0.97, 3 false positives / 60 legit.**
- **Transformer comparison (RQ2):** frozen multilingual MiniLM embeddings + LR
  scored **~64%** vs TF-IDF **~96%** — the lightweight model wins on this dataset.
  Caveat: embeddings frozen, not fine-tuned.
- **Gateway (RQ3):** end-to-end demo — a live `nmap` port scan is detected by
  Suricata and surfaces as a plain-Nepali warning in the app.

---

## Repository layout

```
backend/        FastAPI app (analyze, emergency, lessons, network, alerts)
ai/             training + evaluation (train_eval.py, compare_transformer.py)
data/           dataset (raw/ and original backup are gitignored — unanonymised)
netscan/        gateway scripts: netreport.py, network_rules.json,
                alert_report.py, alert_rules.json
docs/           DEVLOG.md, RQ2_RESULTS.md, EVALUATION_STUDY.md, GATEWAY_SETUP.md
study/          evaluation materials + results spreadsheet
(CyberSaathi-mobile)  Flutter app (lib/main.dart, local_engine.dart, rules JSON)
```

## Running it

- **Backend:** deployed on Render (`https://cybersaathi-gmrv.onrender.com`). Local:
  `uvicorn app.main:app` (run without `--reload` on Python 3.14).
- **App:** `flutter run` (Android device or Chrome). Voice needs a real Android
  phone for Nepali speech.
- **Gateway:** see `docs/GATEWAY_SETUP.md` to reproduce on a Kali VM.

---

## Security & ethics

- Dataset anonymised (phone → `[PHONE]`, name → `[NAME]`, email → `[EMAIL]`,
  long numbers → `[NUMBER]`; amounts/brands/domains kept). Raw un-anonymised data
  stays **gitignored**.
- No secrets in the repo. VirusTotal used for hash/URL lookups only — never
  uploads user files. Official domains verified before any whitelist entry.
- Network scanning is limited to **user-owned** networks. The lab is an isolated
  VirtualBox Host-Only network; Metasploitable2 is **never** bridged.
- Production uses HTTPS; the dev-only cleartext flag was removed from the app.

## Honest limitations

- Dataset is modest and Nepal-specific; results are indicative, not definitive.
- The evaluation study is **designed and ready to run** (materials + spreadsheet)
  but requires participants and ethics approval — not yet run.
- Backend keeps the latest scan/alert in memory (lost on free-tier restart).
- Nepali text-to-speech voice availability varies by device.
- The gateway is a lab proof-of-concept; a real deployment would run on dedicated
  hardware (e.g. a Raspberry Pi) with a threat-intel feed.
