#!/usr/bin/env python3
"""List default Wazuh Windows rules that match given event IDs (run on the Wazuh server with sudo).

    sudo python3 find_default_rules.py 4719,1102,7045
"""
import glob
import re
import sys

wanted = set(sys.argv[1].split(','))
for path in sorted(glob.glob('/var/ossec/ruleset/rules/0*win*.xml')):
    text = open(path, encoding='utf-8', errors='replace').read()
    for m in re.finditer(r'<rule id="(\d+)" level="(\d+)"[^>]*>(.*?)</rule>', text, re.S):
        rid, level, body = m.groups()
        ev = re.search(r'win\.system\.eventID"[^>]*>([^<]+)<', body)
        if not ev:
            continue
        hits = wanted & set(re.findall(r'\d+', ev.group(1)))
        if not hits:
            continue
        parent = re.search(r'<if_sid>([^<]+)</if_sid>', body)
        chan = re.search(r'win\.system\.channel"[^>]*>([^<]+)<', body)
        desc = re.search(r'<description>([^<]+)</description>', body)
        print(f"{path.rsplit('/', 1)[1]:<32} rule {rid:>6} lvl {level:>2} events {','.join(sorted(hits)):<10} "
              f"parent={parent.group(1) if parent else '-':<12} {('chan=' + chan.group(1)) if chan else ''} :: "
              f"{desc.group(1)[:70] if desc else ''}")
