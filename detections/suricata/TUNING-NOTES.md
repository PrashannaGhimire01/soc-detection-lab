# Tuning note: port scan rule (sid 1000002)

## Problem found during testing (2026-10-13)
- A real scan from DC01 (10.10.10.20) did NOT fire: original threshold (20 SYN / 5s)
  was too high for a slow PowerShell-based scan. False negative.
- SIEM01 (10.10.10.10) normal management traffic DID fire the scan rule. False positive.

## Fix
- Lowered threshold to 15 SYN / 10s (rev 2) to catch slower scans.
- Added pass rule (sid 1000099) to allowlist SIEM01 management traffic.

## Result
- Scan from 10.10.10.20 now detected; 10.10.10.10 no longer alerts.
- Lesson: thresholds trade false negatives vs false positives; infrastructure
  hosts should be allowlisted.
