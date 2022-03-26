#!/bin/bash
echo "[*] Installing auditd"
apt update && apt install -y auditd mawk
echo "[*] Setting up auditd rules"
cp audit.rules.template /etc/audit/rules.d/audit.rules
sed -i 's/log_format =.*/log_format = ENRICHED/g' /etc/audit/auditd.conf
systemctl restart auditd

echo "[*] Installing pnat"
rm -rf /var/lib/pnat
mkdir /var/lib/pnat
cp ./tracker.py /var/lib/pnat/tracker.py
cp ./correlate.sh /usr/bin/pnat
chmod +x /usr/bin/pnat
cp ./systemd/pnat.service /etc/systemd/system/pnat.service
systemctl daemon-reload
