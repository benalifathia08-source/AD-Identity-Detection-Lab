#!/usr/bin/env python3
"""Check the alerts produced by a live test suite (run on the Wazuh server with sudo).

    sudo python3 check_test_alerts.py <start_utc YYYY-MM-DDTHH:MM:SS> <expectations.json> [wait-seconds]

Each expectation:
    {"name": "...", "agent": "DC01", "eventID": "4719",
     "match": {"eventdata.subjectUserName": "Administrator"},   # optional, exact field values under data.win
     "match_re": {"eventdata.targetFilename": "PSScriptPolicyTest"},  # optional, case-insensitive regex
     "expect_rule": "100510", "expect_level": 12}
"expect_rule": "none" passes when no matching event produced a custom (1005xx) alert.
Exit code 0 only if every expectation passes.
"""
import json
import re
import sys
import time
from datetime import datetime, timezone


def get(d, dotted):
    for part in dotted.split('.'):
        if not isinstance(d, dict):
            return None
        d = d.get(part)
    return d


start = datetime.strptime(sys.argv[1], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
with open(sys.argv[2], encoding='utf-8') as fh:
    expectations = json.load(fh)
time.sleep(int(sys.argv[3]) if len(sys.argv) > 3 else 0)

alerts = []
with open('/var/ossec/logs/alerts/alerts.json', encoding='utf-8', errors='replace') as fh:
    for line in fh:
        try:
            a = json.loads(line)
        except ValueError:
            continue
        if datetime.strptime(a['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z') >= start:
            alerts.append(a)

passed = 0
for e in expectations:
    hits = []
    for a in alerts:
        win = a.get('data', {}).get('win', {})
        if a.get('agent', {}).get('name') != e['agent'] or win.get('system', {}).get('eventID') != e['eventID']:
            continue
        if all(get(win, k) == v for k, v in e.get('match', {}).items()) and \
           all(re.search(v, str(get(win, k) or ''), re.I) for k, v in e.get('match_re', {}).items()):
            hits.append((a['rule']['id'], a['rule']['level'], a['rule']['description']))
    if e['expect_rule'] == 'none':
        ok = not any(r.startswith('1005') for r, _, _ in hits)
    else:
        ok = any(r == e['expect_rule'] and l == e['expect_level'] for r, l, _ in hits)
    passed += ok
    want = 'no custom alert' if e['expect_rule'] == 'none' else f"{e['expect_rule']}/{e['expect_level']}"
    got = '; '.join(sorted({f'{r}/{l}' for r, l, _ in hits})) or 'no alert'
    print(f"{'PASS' if ok else 'FAIL'}  {e['name']:<60} expected {want:<16} got {got}")
    for r, l, d in hits:
        if r.startswith('1005'):
            print(f'      {d[:130]}')
            break
print(f'\n{passed}/{len(expectations)} passed')
sys.exit(0 if passed == len(expectations) else 1)
