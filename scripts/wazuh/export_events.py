#!/usr/bin/env python3
"""Export raw Windows events from the Wazuh archive as test samples (run on the Wazuh server with sudo).

    sudo python3 export_events.py <agent> <eventIDs comma-separated> <minutes back> <out-dir>

Each event is written as one JSON file holding the original log line ("full_log"), which is exactly
what the agent sent, so it can be replayed through wazuh-logtest later.
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone

agent, ids, minutes, out_dir = sys.argv[1], set(sys.argv[2].split(',')), int(sys.argv[3]), sys.argv[4]
since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
os.makedirs(out_dir, exist_ok=True)

n = 0
with open('/var/ossec/logs/archives/archives.json', encoding='utf-8', errors='replace') as fh:
    for line in fh:
        if f'"{agent}"' not in line:
            continue
        try:
            a = json.loads(line)
        except ValueError:
            continue
        if datetime.strptime(a['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z') < since:
            continue
        win = a.get('data', {}).get('win', {})
        eid = win.get('system', {}).get('eventID')
        if eid not in ids or 'full_log' not in a:
            continue
        group = win.get('eventdata', {}).get('targetUserName', 'na').replace(' ', '_')
        name = f"{eid}_{group}_{a['timestamp'][11:19].replace(':', '')}.json"
        with open(os.path.join(out_dir, name), 'w', encoding='utf-8') as out:
            json.dump({'agent': agent, 'location': a.get('location', 'EventChannel'), 'full_log': a['full_log']}, out, indent=2)
        n += 1
print(f'exported {n} events to {out_dir}')
