#!/usr/bin/env python3
"""Summarize recent Wazuh alerts per agent and rule (run on the Wazuh server with sudo).

    sudo python3 alert_summary.py [minutes] [agent-name]
"""
import json
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

minutes = int(sys.argv[1]) if len(sys.argv) > 1 else 15
agent_filter = sys.argv[2] if len(sys.argv) > 2 else None
since = datetime.now(timezone.utc) - timedelta(minutes=minutes)

counts = Counter()
with open('/var/ossec/logs/alerts/alerts.json', encoding='utf-8', errors='replace') as fh:
    for line in fh:
        try:
            a = json.loads(line)
        except ValueError:
            continue
        ts = datetime.strptime(a['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z')
        if ts < since:
            continue
        agent = a.get('agent', {}).get('name', '?')
        if agent_filter and agent != agent_filter:
            continue
        win = a.get('data', {}).get('win', {}).get('system', {})
        counts[(agent, a['rule']['id'], a['rule']['level'], win.get('eventID', '-'), a['rule']['description'][:70])] += 1

print(f'Alerts in the last {minutes} min' + (f' for {agent_filter}' if agent_filter else ''))
for (agent, rid, lvl, eid, desc), n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
    print(f'{n:5}  {agent:10} rule {rid:>6} lvl {lvl:>2}  event {eid:>5}  {desc}')
