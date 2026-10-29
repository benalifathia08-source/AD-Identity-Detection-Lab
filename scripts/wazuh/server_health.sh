#!/bin/bash
# Wazuh server health and growth check (run with sudo). Read-only.
echo "== version";      /var/ossec/bin/wazuh-control info | tr '\n' ' '; echo
echo "== packages";     dpkg -l 'wazuh-*' 2>/dev/null | awk '/^ii/ {print $2, $3}'
echo "== services";     for s in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do echo "$s: $(systemctl is-active $s)"; done
echo "== time";         timedatectl | grep -E 'Local time|synchronized'
echo "== disk";         df -h / | tail -1
echo "== ossec logs";   du -sh /var/ossec/logs/alerts /var/ossec/logs/archives 2>/dev/null
echo "== today's archive and alert files"
ls -lh /var/ossec/logs/archives/archives.json /var/ossec/logs/alerts/alerts.json 2>/dev/null | awk '{print $5, $9}'
echo "== indexer data"; du -sh /var/lib/wazuh-indexer 2>/dev/null
echo "== filebeat archives module"; grep -A2 'archives:' /etc/filebeat/filebeat.yml 2>/dev/null | tr -s ' '
echo "== retention cron/logrotate for archives"; ls /etc/cron.d/ 2>/dev/null; grep -rl ossec /etc/logrotate.d/ 2>/dev/null
echo "== agents";       /var/ossec/bin/agent_control -l | grep -E 'ID:'
echo "== sshd auth";    sshd -T 2>/dev/null | grep -E '^(passwordauthentication|permitrootlogin|pubkeyauthentication) '
echo "== sudoers lab";  ls -l /etc/sudoers.d/ 2>/dev/null
echo "== ufw";          ufw status 2>/dev/null | head -3
echo "== upgradable wazuh"; apt list --upgradable 2>/dev/null | grep -i wazuh || echo "(none listed; apt cache may be stale)"
