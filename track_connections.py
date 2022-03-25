#!/usr/bin/python3
import sys
import re
import concurrent.futures
import threading

# A dictionary to keep track of all network events to be processed
active_connections = {}
# I'm not sure a dictionary is thread safe when add/removes happen in parallel, so I rely on a simple lock
active_connections_lock = threading.Lock()

# For every new exited process, find if the connection tracker found any network event related to it. Log everything that is found.
# This consumes the dictionary produced by conns_tracker()
def closed_tracker():
	print("Started closed_tracker")
	with open('/var/lib/pnat/logs.log', 'a') as logfile:
		# Resilient fifo follower
		with open('/var/lib/pnat/close.fifo') as closefifo:
			while True:
				closeline = closefifo.readline()
				if len(closeline) == 0:
					print("Closed writer closed")
					break
				closesplit = closeline.split(' ')
				closepid = closesplit[1]
				closetime = closesplit[0]
				closeexe = closesplit[2].replace('\n','')

				# Read connfile after we got a closeline, so we're sure that if the closed process did some network activity, we will find it in connfile
				with active_connections_lock:
					# get event keys with correct PID and that happened before the process died
					# we cannot use a list generator because we need to get all the keys before popping
					# a.k.a. we cannot pop in the dictionary while looping through it
					keyslist = [key for key in active_connections.keys() if int(key[1]) == int(closepid) and float(key[0]) <= float(closetime)]
					for key in keyslist:
						connline = active_connections.pop(key)
						conntime = key[0]
						connip = connline.split(' ')[1]
						print("exe={} ip={} start={} end={}".format(closeexe, connip, conntime, closetime))
						logfile.write("exe={} ip={} start={} end={}\n".format(closeexe, connip, conntime, closetime))
					logfile.flush()

# For every new network event, grow a dictionary (timestamp,pid):(event metadata). This works as a producer.
def conns_tracker():
	print("Started conns_tracker")
	with open('/var/lib/pnat/conn.fifo') as connfifo:
		while True:
			connline = connfifo.readline()
			if len(connline) == 0:
				print("Conns writer closed")
				break
			connsplit = connline.split(' ')
			connpid = connsplit[2]
			conntime = connsplit[0]
			# Use (conntime, connpid) as dict key
			with active_connections_lock:
				active_connections[(conntime, connpid)] = connline


with concurrent.futures.ThreadPoolExecutor() as executor:
	futures = [executor.submit(conns_tracker), executor.submit(closed_tracker)]
	for future in concurrent.futures.as_completed(futures):
		try:
			result = future.result()
		except OSError as oserror:
			print("[!] OSError: {}".format(oserror), file=sys.stderr)
