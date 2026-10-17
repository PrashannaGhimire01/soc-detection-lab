#!/usr/bin/env python3
"""
Detection-as-Code test harness for the Himal Traders SOC Detection Lab.

Validates, with no network dependency, that every detection in the repo is
structurally sound and internally consistent:

  1. Sigma rules   - parse as YAML, have a valid UUID id, a title, a status,
                     and a detection or correlation body.
  2. Wazuh ruleset - well-formed XML; rule IDs unique and in the 100000-120000
                     custom range; every rule has a description, a level (0-16)
                     and a group; every if_sid / if_matched_sid that points at a
                     custom rule points at one that actually exists.
  3. Consistency   - every runbook filename's leading rule ID exists in the
                     Wazuh ruleset (no runbooks for rules that don't exist).

Exit code 0 = all checks passed, 1 = one or more failures (so CI goes red).
Run:  python3 tests/validate_detections.py
"""
import sys
import os
import glob
import re
import uuid
import xml.etree.ElementTree as ET

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required (pip install pyyaml)")
    sys.exit(2)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGMA_DIR = os.path.join(ROOT, "detections", "sigma")
WAZUH_FILE = os.path.join(ROOT, "detections", "wazuh", "local_rules.xml")
RUNBOOK_DIR = os.path.join(ROOT, "runbooks")

CUSTOM_MIN, CUSTOM_MAX = 100000, 120000

errors = []
passed = 0


def ok(msg):
    global passed
    passed += 1


def fail(msg):
    errors.append(msg)


def is_uuid(value):
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


# ---------------------------------------------------------------------------
# 1. Sigma rules
# ---------------------------------------------------------------------------
def validate_sigma():
    files = sorted(glob.glob(os.path.join(SIGMA_DIR, "*.yml")))
    if not files:
        fail("No Sigma rules found in detections/sigma/")
        return 0
    docs = 0
    for f in files:
        name = os.path.basename(f)
        try:
            parsed = list(yaml.safe_load_all(open(f, encoding="utf-8")))
        except yaml.YAMLError as e:
            fail(f"[sigma] {name}: invalid YAML ({e})")
            continue
        for doc in parsed:
            if not isinstance(doc, dict):
                continue
            docs += 1
            label = f"{name} (title={doc.get('title', '?')!r})"
            if not doc.get("title"):
                fail(f"[sigma] {label}: missing title")
            if not is_uuid(doc.get("id")):
                fail(f"[sigma] {label}: id is not a valid UUID ({doc.get('id')!r})")
            if not doc.get("status"):
                fail(f"[sigma] {label}: missing status")
            if "detection" not in doc and "correlation" not in doc:
                fail(f"[sigma] {label}: has neither a detection nor a correlation body")
        if parsed:
            ok(name)
    return docs


# ---------------------------------------------------------------------------
# 2. Wazuh ruleset
# ---------------------------------------------------------------------------
def validate_wazuh():
    if not os.path.exists(WAZUH_FILE):
        fail("Wazuh ruleset not found at detections/wazuh/local_rules.xml")
        return set()
    raw = open(WAZUH_FILE, encoding="utf-8").read()
    # The file has multiple top-level <group> elements only if edited oddly;
    # wrap in a root so ElementTree can always parse it.
    try:
        root = ET.fromstring(f"<root>{raw}</root>")
    except ET.ParseError as e:
        fail(f"[wazuh] local_rules.xml is not well-formed XML: {e}")
        return set()

    rules = root.findall(".//rule")
    if not rules:
        fail("[wazuh] no <rule> elements found")
        return set()

    ids = []
    for r in rules:
        rid = r.get("id")
        label = f"rule id={rid}"
        # id numeric + in custom range
        if rid is None or not rid.isdigit():
            fail(f"[wazuh] {label}: id missing or not numeric")
            continue
        n = int(rid)
        ids.append(n)
        if not (CUSTOM_MIN <= n <= CUSTOM_MAX):
            fail(f"[wazuh] {label}: id {n} outside custom range {CUSTOM_MIN}-{CUSTOM_MAX}")
        # level present and sane
        lvl = r.get("level")
        if lvl is None or not lvl.isdigit() or not (0 <= int(lvl) <= 16):
            fail(f"[wazuh] {label}: level missing or out of range 0-16 ({lvl!r})")
        # description present and non-empty
        desc = r.find("description")
        if desc is None or not (desc.text and desc.text.strip()):
            fail(f"[wazuh] {label}: missing or empty <description>")
        # group present
        if r.find("group") is None:
            fail(f"[wazuh] {label}: missing <group>")

    custom_ids = set(ids)

    # uniqueness
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        fail(f"[wazuh] duplicate rule IDs: {sorted(dupes)}")

    # dependency check: custom if_sid / if_matched_sid must resolve
    for r in rules:
        rid = r.get("id")
        for tag in ("if_sid", "if_matched_sid"):
            for el in r.findall(tag):
                if el.text is None:
                    continue
                for ref in re.split(r"[,\s]+", el.text.strip()):
                    if ref.isdigit() and int(ref) >= CUSTOM_MIN and int(ref) not in custom_ids:
                        fail(f"[wazuh] rule {rid}: {tag} references custom rule "
                             f"{ref} which does not exist in this file")
    ok("local_rules.xml")
    return custom_ids


# ---------------------------------------------------------------------------
# 3. Consistency: runbooks map to real rules
# ---------------------------------------------------------------------------
def validate_consistency(custom_ids):
    runbooks = sorted(glob.glob(os.path.join(RUNBOOK_DIR, "*.md")))
    if not runbooks:
        fail("No runbooks found in runbooks/")
        return 0
    for rb in runbooks:
        name = os.path.basename(rb)
        m = re.match(r"^(\d{6})_", name)
        if not m:
            fail(f"[runbook] {name}: filename must start with a 6-digit rule ID")
            continue
        rid = int(m.group(1))
        if rid not in custom_ids:
            fail(f"[runbook] {name}: rule ID {rid} is not defined in the Wazuh ruleset")
        else:
            ok(name)
    return len(runbooks)


def main():
    print("=" * 60)
    print(" Detection-as-Code validation - Himal Traders SOC lab")
    print("=" * 60)

    sigma_docs = validate_sigma()
    custom_ids = validate_wazuh()
    runbook_count = validate_consistency(custom_ids)

    print(f"\n  Sigma rule documents : {sigma_docs}")
    print(f"  Wazuh custom rules   : {len(custom_ids)}")
    print(f"  Runbooks             : {runbook_count}")
    print(f"  Checks passed        : {passed}")

    if errors:
        print(f"\n  FAILED ({len(errors)} issue(s)):")
        for e in errors:
            print(f"    - {e}")
        print("\nRESULT: FAIL")
        return 1
    print("\nRESULT: PASS - all detections valid and consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
