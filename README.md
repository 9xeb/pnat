# PNAT (Process Network Activity Tracker)
This is PNAT (Process Network Activity Tracker), a daemon written in bash and python that leverages auditd to __keep track of network activity__ generated by linux processes.
It comes with specifically crafted auditd rules to trace all syscalls associated with network traffic (connect, accept, sendmsg, receivemsg, ...) and process exit syscalls.

It is made of two components: a bash parser and a python tracker/logger.
Bash takes care of following audit logs in real time and writes into two named pipes: conn.fifo and close.fifo.
conn.fifo contains single network event records:
| timestamp  | ip | pid | euid | exe | 
| ---------- | -- | --- | ---- | --- |

close.fifo contains process exits events:
| timestamp  | pid | exe | 
| ---------- | --- | --- |

Python reads from these two named pipes and implements a multithreaded consumer/producer pattern.
A producer reads from conn.fifo and keeps a dictionary of network events to process. One dictionary record looks like this: (timestamp,pid):record

A consumer reads from close.fifo and matches each of its records by consuming entries of the dictionary of tracked connections. 
For each exited process it looks for network events that happened with its PID and before the PID exited. 
When a network event is hit, it is removed from the dictionary. This is what makes the consumer/producer pattern work. 
It logs what it finds.

The result is a grepable logfile containing executable names, IPs they communicated with and a time frame during which network events certainly happened.

PNAT is written with the intent of enriching alerts that come from any kind of network related logs.

Install
```bash
 # ./install_dependencies.sh
```

Setup auditd
```bash
 # ./setup_auditd_local.sh
```

Run
```bash
 # ./correlate.sh
```


### How it works
PNAT queries auditd for the following list of 'starter' system calls:
 * connect
 * accept
 * sendto
 * sendmsg
 * recvfrom
 * recvmsg

For each exit event, it matches the 'starter' calls made by the same PID and before the exit event.

The choice of monitoring from connect/accept/sendmsg/... to exit/exit_group was made because, 
it is better to keep a record of potentially malicious processes until 24 hours after their death 
and in case they run without interruption for days or weeks, we need to be able to track their activity for at least as long as they live. 

### Why monitor exit calls?
Because by just monitoring network 'starter' calls, very little context is provided to determine a time frame during which malicious network activity happened 
Ideally we should close the time frame when a network socket close happens, but there is no way in auditd to distinguish network sockets from any other socket. Recording all socket close calls and then applying some filtering would be tremendously resource intensive since processes die once but may close several sockets. 
Therefore, I chose to extend the time frame from a 'starter' syscall up until the process exit call. It is my attempt to contain resource usage while making sure usable data for intelligence is generated. 

### TODO:
 - some install scripts for centralized auditd collection
 - adapt pnat to process logs from different hosts (add host field) when centralized auditd is configured
