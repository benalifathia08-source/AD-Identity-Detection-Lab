#!/bin/bash
# Wazuh server hardening (run with sudo). Safe to re-run.
#   1. SSH: key-only login (password login off). The VMware console still works with the password.
#      Revert: remove /etc/ssh/sshd_config.d/10-lab-keys-only.conf and run: systemctl reload ssh
#   2. Host firewall (ufw): from the lab subnet only, allow SSH (22), dashboard (443) and agent traffic
#      (1514 events, 1515 enrollment). The API (55000) is only used by the dashboard on localhost, and the
#      indexer (9200/9300) already listens on localhost only. Revert: ufw disable
set -e
LAB=192.168.145.0/24

echo "== SSH"
cat > /etc/ssh/sshd_config.d/10-lab-keys-only.conf <<'EOF'
# Lab hardening: key-based login only
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
sshd -t
systemctl reload ssh
sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication|permitrootlogin|pubkeyauthentication) '

echo "== firewall"
ufw --force reset > /dev/null
ufw default deny incoming > /dev/null
ufw default allow outgoing > /dev/null
for p in 22 443 1514 1515; do ufw allow from $LAB to any port $p proto tcp comment "lab $p" > /dev/null; done
ufw --force enable > /dev/null
ufw status numbered
