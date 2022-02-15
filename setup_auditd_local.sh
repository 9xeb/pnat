#!/bin/bash

# install, load process auditing config, restart daemon
apt update && apt install auditd
if [[ -z "$1" ]]; then
  echo "[*] Hostname is not set, proceeding with local installation"
  cp audit.rules.template /etc/audit/rules.d/audit.rules
else
  echo "[*] Hostname is set, proceeding with remote forwarding"
  apt install audispd-plugins
  echo "[*] Activate remote forwarding"
  sed -i 's/active = no/active = yes/g' /etc/audit/plugins.d/au-remote.conf
  echo "[*] Set remote server address to ""$1"
  sed -i 's/remote_server =.*/remote_server = '"$1"'/g' /etc/audit/audisp-remote.conf
  echo "[*] Do not record logs locally"
  sed -i 's/log_format =.*/log_format = NOLOG/g' /etc/audit/auditd.conf
fi
sudo systemctl restart auditd
