#!/bin/bash
# Require a password for new Wazuh agent enrollments (run on the Wazuh server with sudo).
# The password is random, stored only in /var/ossec/etc/authd.pass (root:wazuh, 640) and never printed.
# Agents that are already enrolled keep their keys and are unaffected.
# To enroll a new agent later: sudo cat /var/ossec/etc/authd.pass   and pass it as WAZUH_REGISTRATION_PASSWORD.
set -e
OSSEC=/var/ossec
if [ ! -s $OSSEC/etc/authd.pass ]; then
  umask 077
  openssl rand -base64 32 | tr -d '\n' > $OSSEC/etc/authd.pass
  echo "authd.pass created"
else
  echo "authd.pass already present"
fi
chown root:wazuh $OSSEC/etc/authd.pass
chmod 640 $OSSEC/etc/authd.pass
cp -a $OSSEC/etc/ossec.conf $OSSEC/etc/ossec.conf.bak-$(date +%Y%m%d%H%M)
sed -i 's|<use_password>no</use_password>|<use_password>yes</use_password>|' $OSSEC/etc/ossec.conf
grep -q '<use_password>yes</use_password>' $OSSEC/etc/ossec.conf && echo "use_password: yes"
systemctl restart wazuh-manager
sleep 20
echo "manager: $(systemctl is-active wazuh-manager)"
$OSSEC/bin/agent_control -l | grep -E 'DC01|WS01'
