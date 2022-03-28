#!/usr/bin/python3

import sys
import re
import concurrent.futures
import threading

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
def closed_tracker(condition):
	print("Started closed_tracker")
	with open('/var/lib/pnat/pnat.log', 'a') as logfile:
		# Resilient fifo follower
		with open('/var/lib/pnat/close.fifo') as closefifo:
			while True:
				closeline = closefifo.readline()
				if len(closeline) == 0:
					print("Closed writer closed")
					break
				closesplit = closeline.split(' ')
				closepid = int(closesplit[1])
				closetime = int(closesplit[0].split('.')[0])
				closeexe = closesplit[2].replace('\n','')

				# Read connfile after we got a closeline, so we're sure that if the closed process did some network activity, we will find it in connfile
				with active_connections_lock:
					# get event keys with correct PID and that happened before the process died
					# we cannot use a list generator because we need to get all the keys before popping
					# a.k.a. we cannot pop in the dictionary while looping through it
					keyslist = [key for key in active_connections.keys() if key[1] == closepid and key[0] <= closetime]
					for key in keyslist:
						connline = active_connections.pop(key)
						conntime = key[0]
						connip = connline.split(' ')[1]
						print("[closed] exe={} ip={} start={} end={}".format(closeexe, connip, conntime, closetime))
						logfile.write("[closed] exe={} ip={} start={} end={}\n".format(closeexe, connip, conntime, closetime))
					logfile.flush()

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
def conns_tracker(condition, parsed_keys={0}):
	print("Started conns_tracker")
	with open('/var/lib/pnat/pnat.log', 'a') as logfile:
		with open('/var/lib/pnat/conn.fifo') as connfifo:
			while True:
				connline = connfifo.readline()
				if len(connline) == 0:
					print("Conns writer closed")
					break
				connsplit = connline.split(' ')
				connpid = int(connsplit[2])
				conntime = int(connsplit[0].split('.')[0])
				connip = connsplit[1]
				connexe = connsplit[3].replace('\n','')

				# forget more than 1 second old entries to avoid memory leaks
				temp = {timestamp for timestamp in parsed_keys if conntime <= timestamp}
				parsed_keys = temp

				# Use (conntime, connpid) as dict key
				with active_connections_lock:
					# if new record is not in parsed keys of the current second
					if conntime not in parsed_keys:
						parsed_keys.add(conntime)
						active_connections[(conntime, connpid)] = connline
						print("[pending] exe={} ip={} start={}".format(connexe, connip, conntime))
						logfile.write("[pending] exe={} ip={} start={}\n".format(connexe, connip, conntime))
						logfile.flush()


				# Update timestamp of the last processed record AFTER it's actually been processed
				# Symmetrical to closed_tracker, however we notify here instead of waiting
				with condition:
					last_conn_timestamp = conntime
					if last_conn_timestamp > last_closed_timestamp:
						#print("Conn notifying")
						condition.notifyAll()


with concurrent.futures.ThreadPoolExecutor() as executor:
	cv = threading.Condition()
	futures = [executor.submit(conns_tracker, condition=cv, parsed_keys={0}), executor.submit(closed_tracker, condition=cv)]
	for future in concurrent.futures.as_completed(futures):
		try:
			result = future.result()
		except OSError as oserror:
			print("[!] OSError: {}".format(oserror), file=sys.stderr)
