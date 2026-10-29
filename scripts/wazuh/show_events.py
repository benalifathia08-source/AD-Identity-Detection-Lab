#!/usr/bin/env python3
"""Show raw decoded fields of recent events from the Wazuh archive (run on the Wazuh server with sudo).

    sudo python3 show_events.py <minutes> <eventIDs comma-separated> [agent]

Prints the rule that fired (if any, from alerts.json) and every decoded win.* field except the
long message text. Useful when writing a rule: it shows the exact field names Wazuh produces.
"""
import json
import sys
from datetime import datetime, timedelta, timezone

minutes, ids = int(sys.argv[1]), set(sys.argv[2].split(','))
agent = sys.argv[3] if len(sys.argv) > 3 else None
since = datetime.now(timezone.utc) - timedelta(minutes=minutes)


def flatten(d, prefix=''):
    for k, v in d.items():
        key = f'{prefix}.{k}' if prefix else k
        if isinstance(v, dict):
            yield from flatten(v, key)
        elif k != 'message':
            yield key, v


alerts = {}
with open('/var/ossec/logs/alerts/alerts.json', encoding='utf-8', errors='replace') as fh:
    for line in fh:
        a = json.loads(line)
        if datetime.strptime(a['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z') >= since:
            rid = a.get('data', {}).get('win', {}).get('system', {}).get('eventRecordID')
            alerts[(a.get('agent', {}).get('name'), rid)] = f"{a['rule']['id']}/{a['rule']['level']} {a['rule']['description'][:80]}"

with open('/var/ossec/logs/archives/archives.json', encoding='utf-8', errors='replace') as fh:
    for line in fh:
        try:
            a = json.loads(line)
        except ValueError:
            continue
        if datetime.strptime(a['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z') < since:
            continue
        name = a.get('agent', {}).get('name')
        win = a.get('data', {}).get('win', {})
        sysd = win.get('system', {})
        if sysd.get('eventID') not in ids or (agent and name != agent):
            continue
        print(f"=== {a['timestamp'][:19]} {name} event {sysd.get('eventID')} record {sysd.get('eventRecordID')}")
        print(f"    alert: {alerts.get((name, sysd.get('eventRecordID')), 'none')}")
        for k, v in flatten(win):
            if not k.startswith('system.') or k in ('system.channel', 'system.computer', 'system.providerName'):
                print(f'    win.{k} = {str(v)[:120]}')
