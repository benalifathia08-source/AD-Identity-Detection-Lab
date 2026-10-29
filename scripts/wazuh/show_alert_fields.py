#!/usr/bin/env python3
"""Print the decoded win.* fields of recent alerts for given rule IDs (run on the Wazuh server with sudo).

    sudo python3 show_alert_fields.py <minutes> <rule IDs comma-separated> [max per rule]

Used when tuning a rule: shows exactly which field values separate benign events from the rest.
"""
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

minutes, rules = int(sys.argv[1]), set(sys.argv[2].split(','))
per_rule = int(sys.argv[3]) if len(sys.argv) > 3 else 2
since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
shown = defaultdict(int)
total = defaultdict(int)


def flatten(d, prefix=''):
    for k, v in d.items():
        key = f'{prefix}.{k}' if prefix else k
        if isinstance(v, dict):
            yield from flatten(v, key)
        elif k not in ('message', 'taskContent'):
            yield key, v


with open('/var/ossec/logs/alerts/alerts.json', encoding='utf-8', errors='replace') as fh:
    for line in fh:
        a = json.loads(line)
        rid = a['rule']['id']
        if rid not in rules or datetime.strptime(a['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z') < since:
            continue
        total[rid] += 1
        if shown[rid] >= per_rule:
            continue
        shown[rid] += 1
        print(f"=== rule {rid} lvl {a['rule']['level']} {a['agent']['name']} {a['timestamp'][:19]}  {a['rule']['description'][:90]}")
        for k, v in flatten(a.get('data', {}).get('win', {})):
            if not k.startswith('system.') or k in ('system.eventID', 'system.computer'):
                print(f'    win.{k} = {str(v)[:140]}')
print('totals:', dict(total))
