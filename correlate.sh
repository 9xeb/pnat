#!/bin/bash

# requires auditd and sqlite3
# RUN THIS SCRIPT EVERY HOUR LIKE RITA

# TODO: rotate sqlite table every 24 hours (keep the last 24 hours of data, update every hour)
# BUT REMEMBER THAT THIS APPLIES TO CLOSED CONNECTIONS ONLY (a connection with no end time
# is kept forever, or until 24 hours have passed since its end)

# When a network audit of any kind raises a possible alert,
# perform a cross referencing with process audit (run this in the centralized auditd collector)

# The only requirement is that audit.conf is set as setup_auditd.sh does (logging specific syscalls)
# and log_format=enriched is set in /etc/audit/auditd.conf

# more anomalies may rise up from this, namely:
# 1. there are no recorded logs of the suspicious connection (kernel rootkit or software malfunctioning?)
# 2. the connection comes from an unexpected process (super likely incident spotted)

# the goal is to turn high amounts of false positives from network audit into an asset
# and allow the security analyst to identify true positives via easy manual inspection
dir='/var/lib/pnat'

# Auditd Parser for Process Network Activity Tracking
if ! [[ -r "$dir" ]]; then
  sudo mkdir "$dir"
fi

echo "[*] Saving checkpoint as 24 hours ago"
# the following date format is necessary for ausearch to work
date '+%x %H:%M:%S' -d "1 day ago" | sudo tee "$dir"/checkpoint

rm "$dir"/*.fifo
rm "$dir"/*.txt
starttime=$(cat "$dir"/checkpoint)

######## CONNECT & ACCEPT (timestamp, socket, executable) ########
# ipv4 and ipv6

echo "[*] Updating connect/accept/sendto/sendmsg/recvfrom/recvmsg events list"
tail -F /var/log/audit/audit.log 2>/dev/null | grep --line-buffered -e '^type=SOCKADDR' -e '^type=SYSCALL' | \
awk -W interactive '{if($1~/^type=SOCKADDR/) {printf("%s",$0)} else {print $0}}' | \
grep --line-buffered -e '.*saddr_fam=inet.*' -e '.*saddr_fam=inet6.*' | grep --line-buffered -v 'laddr=127.0.0.1' | grep --line-buffered -v 'laddr=::1' | \
awk -W interactive '{split(substr($2,11),a,")"); split(a[1],b,":"); printf b[2]" "} {split(substr($2,11),a,"."); printf a[1]" "} {for(i=1;i<=NF;i++) {if($i~/^pid=/ || $i~/^exe=/) {printf "%s",substr($i,5)" "} if($i~/^euid=/) {printf "%s",substr($i,6)" "} if($i~/^laddr=/) {printf "%s",substr($i,7)" "}}} {print ""}' > "$dir"/connmeta.txt &

# The complex awk program above is made of four major { blocks }:
#   1. Two splits of $2 to retrieve the unique event ID
#   2. Two splits of $2 to retrieve a timestamp (seconds after 01/01/1970)
#   3. A for loop that goes through whitespace separated columns of a line, and matches these columns with regexes to extract a (REMOTE_IP, PID, EUID, EXECUTABLE_PATH) tuple
#   4. A simple trailing newline to end the record


##################################
# I've been thinking about this for quite some time
# it seems very hard to figure out where a previously opened socket was closed because:
# I can't seem to find a way to group syscalls of a same process instance
# therefore there's no guarantee the close() call we find is the right one,
# even if we compare the return fd address of socket() with the argument given to the close() call

# an ok alternative would be to spot when the process calls exit() or exit_group() (first occurrence)

######## ASSOCIATED PROCESS EXIT (timestamp, executable) #######
# auditd records are sorted by timestamp
# so given a connect/accept record, we look for the first following close that has the same PID and socket number
# this way we can find out when (and if) the process has exited
echo "[*] Updating exit/exit_group events list"

# producer (exit)
tail -F /var/log/audit/audit.log 2>/dev/null | \
grep --line-buffered -e '^type=SYSCALL' | grep --line-buffered -e 'pnat_exit' | \
awk -W interactive '{split(substr($2,11),a,")"); split(a[1],b,":"); printf b[2]" "} {split(substr($2,11),a,"."); printf a[1]" "} {for(i=1;i<=NF;i++) {if($i~/^pid=/ || $i~/^exe=/) {printf "%s",substr($i,5)" "}}} {print ""}' > "$dir"/closemeta.txt

##################################
# for each connect/accept event, find the first exit event with the same PID, after the connect/accept timestamp.
# this is how we unambiguously determine a valid time frame to correlate network alerts with
echo "[*] Establishing connections timeframes per process"

closefile="$(cat ""$dir"/"close.fifo)"
mkfifo "$dir"/resultscsv.fifo
while read -r conn
do
  conn_time="$(echo ""$conn"" | cut -d' ' -f 2)"
  conn_pid="$(echo ""$conn"" | cut -d' ' -f 4)"
  #echo "[MATCHING: ""$conn_time"" $conn_pid ""]" 1>&2
  # TODO: implement binary search instead of linear search
  end_flag="0"
  #echo "[!] Testing ""$conn"
  # Match conn entry with first occurrence of same PID exit call
  echo "$closefile" | grep -e "$conn_pid" | \
  { while read -r close
    do
      close_time="$(echo ""$close"" | cut -d' ' -f 2)"
      if [ $close_time -ge $conn_time ]; then
        echo "$close_time"" ""$conn" | awk '{printf("%s", "{\"id\":\""$2"\",\"starttime\":\""$3"\",\"endtime\":\""$1"\",\"addr\":\""$4"\",\"pid\":\""$5"\",\"euid\":\""$6"\",\"exe\":\""$7"\"}")} {print ""}'
        #echo "[""$close""]"" -> ""[""$conn""]" 1>&2
        # break at first occurrence
        end_flag="1"
        break
      fi
    done;
    # the connection has started but the process is still running
    if [[ "$end_flag" == "0" ]]; then
      echo "$conn" | awk '{printf("%s", "{\"id\":\""$1"\",\"starttime\":\""$2"\",\"endtime\":\"0\",\"addr\":\""$3"\",\"pid\":\""$4"\",\"euid\":\""$5"\",\"exe\":\""$6"\"}")} {print ""}'
    fi
  }
done < "$dir"/conn.fifo | (read -r first && jq -r '( [.[]] | @csv)' <<<"${first}" && jq -r '[.[]] | @csv') > "$dir"/resultscsv.fifo && rm "$dir"/conn.fifo "$dir"/close.fifo &

echo "[*] Building/Updating database"
# create table metadata
echo -e "CREATE TABLE IF NOT EXISTS \"procs\"(\n  \"id\" TEXT,\n  \"starttime\" TEXT,\n  \"endtime\" TEXT,\n  \"addr\" TEXT,\n  \"pid\" TEXT,\n  \"euid\" TEXT,\n  \"exe\" TEXT,\n  PRIMARY KEY (id, starttime)\n);" | sqlite3 "$dir"/intel.sqlite

# csv to sqlite3 (do not print insert errors due to repeated entries)
echo -e ".mode csv\n.import ""$dir""/resultscsv.fifo procs\n.exit" | sqlite3 "$dir"/intel.sqlite 2>/dev/null
rm "$dir"/resultscsv.fifo

# remove entries with endtime older than N seconds after checkpoint (default 86400 seconds -> 24 hours)
checkpoint_date=$(date --file="$dir"/checkpoint '+%s')
echo -e "DELETE FROM procs WHERE ""$checkpoint_date""-endtime > 86400;" | sqlite3 "$dir"/intel.sqlite
