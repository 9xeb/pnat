#!/usr/bin/python3

# TODO: improve code quality using decorators to reuse most of the code

import sys, os, syslog
import re
import concurrent.futures, threading
import json

syslog.openlog(ident="pnat[%s]" % os.getpid(), facility=syslog.LOG_DAEMON)
# A dictionary to keep track of all network events to be processed
active_connections = {}
# I'm not sure a dictionary is thread safe when add/removes happen in parallel, so I rely on a simple lock
active_connections_lock = threading.Lock()
#parsed_keys = ()

# used to keep the two threads synchronized via conditions
last_closed_timestamp = float(0.0)
last_conn_timestamp = float(0.0)

# For every new exited process, find if the connection tracker found any network event related to it. Log everything that is found.
# This consumes the dictionary produced by conns_tracker()
def closed_tracker(condition, parsed_keys={0}):
	print("Started closed_tracker")
	with open('/var/log/pnat/pnat.log', 'a') as logfile:
		# Resilient fifo follower
		with open('/var/lib/pnat/close.fifo') as closefifo:
			while True:
				closeline = closefifo.readline()
				if len(closeline) == 0:
					print("Closed writer closed")
					break
				closejson = json.loads(closeline)
				closepid = int(closejson['pid'])
				closetime = int(closejson['end'].split('.')[0])
				closeexe = closejson['exe']

				# TODO: use parsed_keys to make closed_tracker faster (skip duplicate entries in the same second)

				# Read connfile after we got a closeline, so we're sure that if the closed process did some network activity, we will find it in connfile
				with active_connections_lock:
					# get event keys with correct PID and that happened before the process died
					# we cannot use a list generator because we need to get all the keys before popping
					# a.k.a. we cannot pop in the dictionary while looping through it
					keyslist = [key for key in active_connections.keys() if key[2] == closepid and key[0] <= closetime]
					for key in keyslist:	# for each (start,ip,pid) tuple, with the same pid as closepid and older start timestamp than closetime
						connjson = json.loads(active_connections.pop(key))
						conntime = connjson['start']	# already made to integer by conns_tracker
						connip = connjson['ip']
						close_json = json.dumps({'type': 'closed', 'start': conntime, 'end': closetime, 'ip': connip, 'exe': closeexe})
						#print("{}".format(close_json))
						#logfile.write("{}\n".format(close_json))
						syslog.syslog("{}".format(close_json))
					#logfile.flush()

				# smart synchronization with Condition
				# checks are done in both threads, so that there is no way of breaking flow integrity
				# closed_tracker must not overtake conns_tracker so it is ensured that for each "closed" record all previous "conns" records have already been processed
				with condition:
					last_closed_timestamp = float(closetime)
					if last_closed_timestamp <= last_conn_timestamp:
						#print("Close waiting")
						condition.wait()


# For every new network event, grow a dictionary (timestamp,pid):(event metadata). This works as a producer.
# Unique parsed keys (used to avoid logging duplicate entries in the last second). This reduces log output by a lot.
def conns_tracker(condition, parsed_keys={(0,'',0)}):
	print("Started conns_tracker")
	with open('/var/log/pnat/pnat.log', 'a') as logfile:
		with open('/var/lib/pnat/conn.fifo') as connfifo:
			while True:
				connline = connfifo.readline()
				if len(connline) == 0:
					print("Conns writer closed")
					break
				connjson = json.loads(connline)
				#print("[pending] {}".format(connjson))
				# Parse keys from json
				connpid = int(connjson['pid'])
				conntime = int(connjson['start'].split('.')[0])
				connips = [ connjson[key] for key in connjson.keys() if key.startswith("ip") ]	# all values with keys that start with "ip"
				connexe = connjson['exe']

				# forget entries that are more than 1 second old to avoid memory leaks
				temp = {key for key in parsed_keys if conntime <= key[0]}
				parsed_keys = temp

				# Do some checks to limit redundancies in the same second, then package a new json
				# Use (conntime, connip) as dict key
				with active_connections_lock:
					for connip in connips:
						# if new record is not in parsed keys of the current (second,ip,pid)
						if (conntime,connip,connpid) not in parsed_keys:
							parsed_keys.add((conntime,connip,connpid))
							stripped_connjson = json.dumps({'type':'pending', 'start': conntime, 'ip': connip, 'exe': connexe})
							active_connections[(conntime, connip, connpid)] = stripped_connjson
							#print("{}".format(stripped_connjson))
							syslog.syslog("{}".format(stripped_connjson))
							#logfile.write("{}\n".format(stripped_connjson))
							#logfile.flush()

				# Update timestamp of the last processed record AFTER it's actually been processed
				# Symmetrical to closed_tracker, however we notify here instead of waiting
				with condition:
					last_conn_timestamp = conntime
					if last_conn_timestamp > last_closed_timestamp:
						#print("Conn notifying")
						condition.notifyAll()


with concurrent.futures.ThreadPoolExecutor() as executor:
	cv = threading.Condition()
	futures = [executor.submit(conns_tracker, condition=cv, parsed_keys={(0,'',0)}), executor.submit(closed_tracker, condition=cv)]
	for future in concurrent.futures.as_completed(futures):
		try:
			result = future.result()
		except OSError as oserror:
			print("[!] OSError: {}".format(oserror), file=sys.stderr)
