#!/bin/bash

# the following script sets an auditd collector
# in order to keep logs in a secure location for further analysis
apt update && apt install auditd audispd-remote sqlite3
sed -i 's/##tcp_listen_port =.*/tcp_listen_port = 60/g' /etc/audit/auditd.conf

