#!/usr/bin/env python3
"""List alerts between two UTC timestamps, at or above a minimum level (run on the Wazuh server with sudo).

    sudo python3 alerts_between.py <from YYYY-MM-DDTHH:MM:SS> <to YYYY-MM-DDTHH:MM:SS> [min-level] [exclude-substring]
"""
import json
import sys
from collections import Counter
from datetime import datetime, timezone

fmt = '%Y-%m-%dT%H:%M:%S'
start = datetime.strptime(sys.argv[1], fmt).replace(tzinfo=timezone.utc)
end = datetime.strptime(sys.argv[2], fmt).replace(tzinfo=timezone.utc)
min_level = int(sys.argv[3]) if len(sys.argv) > 3 else 0
exclude = sys.argv[4] if len(sys.argv) > 4 else None

counts = Counter()
with open('/var/ossec/logs/alerts/alerts.json', encoding='utf-8', errors='replace') as fh:
    for line in fh:
        a = json.loads(line)
        ts = datetime.strptime(a['timestamp'], '%Y-%m-%dT%H:%M:%S.%f%z')
        r = a['rule']
        if not (start <= ts <= end) or r['level'] < min_level or (exclude and exclude in r['description']):
            continue
        counts[(a.get('agent', {}).get('name', '?'), r['id'], r['level'], r['description'][:105])] += 1
for (agent, rid, lvl, desc), n in sorted(counts.items(), key=lambda kv: (-kv[0][2], kv[0][1])):
    print(f'{n:4}  {agent:6} {rid:>6} lvl {lvl:>2}  {desc}')
