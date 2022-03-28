#!/bin/bash

list_descendants ()
{
  local children=$(ps -o pid= --ppid "$1")
  for pid in $children
  do
    list_descendants "$pid"
  done
  echo "$children"
}

kill_tree ()
{
  echo "[!] Killing process tree"
  echo "[!] "$(list_descendants $$)
  kill -9 $(list_descendants $$)
  exit
}
trap kill_tree SIGTERM SIGINT

# requires auditd

# When a network audit of any kind raises a possible alert,
# perform a cross referencing with process audit (run this in the centralized auditd collector)

# The only requirement is that audit.conf is set as setup_auditd.sh does (logging specific syscalls)
# and log_format=enriched is set in /etc/audit/auditd.conf

# more anomalies may rise up from this, namely:
# 1. there are no recorded logs of the suspicious connection (kernel rootkit or software malfunctioning?)
# 2. the connection comes from an unexpected process (super likely incident spotted)

# the goal is to turn high amounts of false positives from network audit into an asset for semi-automated monitoring
# and allow the security analyst to identify true positives via easy manual inspection
dir='/var/lib/pnat'

# Auditd Parser for Process Network Activity Tracking
#if ! [[ -r "$dir" ]]; then
#  sudo mkdir "$dir"
#fi

if ! [[ -x "$dir"/tracker.py ]]; then
  echo "[!] Tracker not found in ""$dir"/tracker.py
  exit 1
fi

rm "$dir"/*.fifo
rm "$dir"/*.txt

mkfifo "$dir"/raw0.fifo
mkfifo "$dir"/raw1.fifo
tail -F /var/log/audit/audit.log 2>/dev/null | tee "$dir"/raw0.fifo "$dir"/raw1.fifo > /dev/null &
######## CONNECT & ACCEPT (timestamp, socket, executable) ########
# ipv4 and ipv6
mkfifo "$dir"/conn.fifo
cat "$dir"/raw0.fifo | grep --line-buffered -e '^type=SOCKADDR' -e '^type=SYSCALL' | \
mawk -W interactive '{if($1~/^type=SOCKADDR/) {printf("%s",$0)} else {print $0}}' | \
grep --line-buffered -e '.*fam=inet.*' -e '.*fam=inet6.*' | grep --line-buffered -v 'laddr=127.0.0.1' | grep --line-buffered -v 'laddr=::1' | \
mawk -W interactive '{split(substr($2,11),a,":"); printf a[1]" "} {for(i=1;i<=NF;i++) {if($i~/^pid=/ || $i~/^exe=/) {printf "%s",substr($i,5)" "} if($i~/^laddr=/) {printf "%s",substr($i,7)" "}}} {print ""}' > "$dir"/conn.fifo &
# The mawk program above is made of 3 main blocks:
#	1. Timestamp of the conn event
#	2. PID,EXE,EUID,IP_ADDRESS
#	3. Newline to end the record
echo "[*] Started connection events parser"

##################################
# I've been thinking about this for quite some time
# it seems very hard to figure out where a previously opened socket was closed because:
# I can't seem to find a way to group syscalls of a same process instance
# therefore there's no guarantee the close() call we find is the right one,
# even if we compare the return fd address of socket() with the argument given to the close() call
# an ok alternative would be to spot when the process calls exit() or exit_group() (first occurrence)

######## ASSOCIATED PROCESS EXIT (timestamp, executable) #######
mkfifo "$dir"/close.fifo
cat "$dir"/raw1.fifo | \
grep --line-buffered -e '^type=SYSCALL' | grep --line-buffered -e 'pnat_exit' | \
mawk -W interactive '{split(substr($2,11),a,":"); printf a[1]" "} {for(i=1;i<=NF;i++) {if($i~/^pid=/ || $i~/^exe=/) {printf "%s",substr($i,5)" "}}} {print ""}' > "$dir"/close.fifo &
# The mawk program above is made of 3 main blocks:
#	1. Timestamp of the exit event
#	2. PID,EXE
#	3. Newline at the end of the record
echo "[*] Started exit events parser"

#cat "$dir"/close.fifo "$dir"/conn.fifo
#exit
#cat "$dir"/close.fifo > /dev/null &
#cat "$dir"/conn.fifo
#exit
# we track connections on a separate single process because if we run bash commands here they get recorded as exit syscalls
# and we get an infinite loop that fills the audit logs
"$dir"/tracker.py
exit
