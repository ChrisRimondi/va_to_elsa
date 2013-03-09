#!/usr/bin/env python
# Copyright (c) 2013, Chris Rimondi
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, 
# are permitted provided that the following conditions are met:
#
#  Redistributions of source code must retain the above copyright notice, this 
#  list of conditions and the following disclaimer.
#
#  Redistributions in binary form must reproduce the above copyright notice, 
#  this list of conditions and the following disclaimer in the documentation 
#  and/or other materials provided with the distribution.
#
#  Neither the name of Chris Rimondi nor the names of its contributors may
#  be used to endorse or promote products derived from this software without
#  specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, 
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
# OF SUCH DAMAGE.

# ELSA    Field Order Information
# Order | Field     	| DB Order  | 
# 0     | timestamp 	|			| 
#1      | host			|
#2      | program name	|
#3      | class			|
#4 		| msg			| 
# i0    | scanID				| 5	
# i1 	| processID				| 6
# i2 	| creationDate			| 7
# i3 	| terminationDate		| 8
# i4 	| parentProcessID		| 9
# i5 	| handle				| 10
# s0 	| processName			| 11
# s1 	| ExecutablePath 		| 12
# s2	| process_host_ip		| 12
# s3 	| OSCreationClassName	| 13
# s4 	| parentProcessName		| 14


import socket
import binascii
import time
import codecs
import struct
import locale
from glob import iglob
import glob
import shutil
import os
import sys
import getopt
import wmi
import re
import Queue
import threading
import pythoncom
import socket

FACILITY = {
	'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
	'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
	'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
	'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
	'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

LEVEL = {
	'emerg': 0, 'alert':1, 'crit': 2, 'err': 3,
	'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}

def syslog(message, level=LEVEL['notice'], facility=FACILITY['daemon'],
	host='localhost', port=514):

	"""
	Send syslog UDP packet to given host and port.
	"""

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	data = '<%d>%s' % (level + facility*8, message)
	sock.sendto(data, (host, port))
	sock.close()

class ProcessFetcher:
	"This clas will fetch all the process information from a host via WMI and ship it out via syslog"
	
	def __init__(self, wmi, scanID, host_ip, scan_time,server):
		self.wmi = wmi
		self.scanID = scanID
		self.ip = host_ip
		self.scan_time = scan_time
		self.server = server
		
	def createHostProcessList(self):
		"Returns a list of dictionaries for each hosts process list"
		c = self.wmi
		list_processes = []
		#print "Inside createHostProcessList"


		for process in c.Win32_Process ():
		  dict_process_info = {}
		  dict_process_info['parentProcessName'] = 'None'
		  dict_process_info['creationDate'] = '0'
		  dict_process_info['terminationDate'] = '0'
		  dict_process_info['scanID'] = self.scanID
		  dict_process_info['full_text'] = str(self.scanID)
		  dict_process_info['processID'] = process.ProcessId 
		  dict_process_info['full_text'] += '|' +  str(dict_process_info['processID'])
		  dict_process_info['creationDate'] = process.CreationDate
		  dict_process_info['full_text'] += '|' +  str(dict_process_info['creationDate'])
		  dict_process_info['terminationDate'] = process.TerminationDate
		  dict_process_info['full_text'] += '|' +  str(dict_process_info['terminationDate'])
		  dict_process_info['parentProcessID'] = process.ParentProcessId
		  dict_process_info['full_text'] += '|' +  str(dict_process_info['parentProcessID'])
		  dict_process_info['ip'] = str(self.ip)
		  dict_process_info['full_text'] += '|' +  str(self.ip)
		  dict_process_info['name'] = process.Name
		  dict_process_info['full_text'] += '|' +  str(dict_process_info['name'])
		  dict_process_info['processExecutablePath'] = process.ExecutablePath
		  dict_process_info['full_text'] += '|' +  str(dict_process_info['processExecutablePath']).replace('|','')
		  dict_process_info['OSName'] = process.OSName
		  dict_process_info['full_text'] += '|' +  str(dict_process_info['OSName']).replace('|','')
		  dict_process_info['handle'] = process.Handle
		  dict_process_info['full_text'] += '|' +  str(dict_process_info['handle'])
		  dict_process_info['OSCreationClassName'] = process.OSCreationClassName
		  dict_process_info['full_text'] += '|' +  str(dict_process_info['OSCreationClassName']).replace('|','')
		  list_processes.append(dict_process_info)
		  #print dict_process_info['full_text']
  

		dict_id_map = {}
		#Dict creation for mapping all process IDs to names, used below to map parent information
		for process in list_processes:
			dict_id_map[process['processID']] = process['name']
			#print dict_id_map[process['processID']]

		for process in list_processes:
			if dict_id_map.has_key(process['parentProcessID']):			
				#print dict_id_map[process['parentProcessID']]
				process['parentProcessName'] = dict_id_map[process['parentProcessID']]
				#print "Evaluated to TRUE: " + process['parentProcessName']
				#print "Full text before: " + process['full_text']
				process['full_text'] += '|' +  process['parentProcessName'] + '|'
				#print "Full text after: " + process['full_text'] + '\n'
			else:
				#print "No parent process name found for process: " + process['name'] + "Parent process ID is: " + str(process['parentProcessID'])
				process['parentProcessName'] = "Cannot locate Parent Process Name"
				#print "Evaluated to FALSE: " + process['parentProcessName']
				#print "Full text before: " + process['full_text']
				process['full_text'] += '|' +  process['parentProcessName'] + '|'
				#print "Full text after: " + process['full_text'] + '\n'
		
		for p in list_processes:
			#print p['full_text']
			#print self.server
			syslog('PROCESS PROCESS ' + p['full_text'], host=self.server)
		return
		
		
class ProcessGetter(threading.Thread):
	"This class will take an input file of hosts and run ProcessFetcher on them and log them to disk in individual files."
	

	def __init__(self, scan_time, scanID, host,user,password,server):
		self.current_scan_time = scan_time
		self.current_scanID = scanID
		self.current_host = host
		threading.Thread.__init__(self)
		self.user = user
		self.password = password
		self.server = server
		
		
	def run(self):
		pythoncom.CoInitialize()
		try:
			print "Connecting to host " + self.current_host + "\n"
			c = wmi.WMI(self.current_host,user=self.user, password=self.password)
			#print "Creating process fetcher object for host " + self.current_host + "\n"
			pf = ProcessFetcher(c, self.current_scanID, self.current_host, self.current_scan_time,self.server)
			#print "Fetching list of processes for host " + self.currenwwt_host + "\n"
			host_process_list = pf.createHostProcessList()
			
		except wmi.x_wmi, x:
			print "Exception number " + str(x.com_error.hresult) + ' with host: '  + self.current_host
			#print str(x) + '\n'
		finally:
			pythoncom.CoUninitialize()
			#print "Done"
		

	
	
#-------------------------#
# Begin the main program. #
#-------------------------#
def create_sql_file(class_num):
	sql_file = """
use syslog;
INSERT INTO classes (id, class) VALUES (%s, "PROCESS");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("scanID", "int", "NUMBER");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("processID", "int", "NUMBER");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("creationDate", "int", "NUMBER");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("terminationDate", "int", "NUMBER");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("parentProcessID", "int", "NUMBER");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("processName", "string", "QSTRING");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("OSName", "string", "QSTRING");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("handle", "string", "NUMBER");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("executablePath", "string", "QSTRING");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("parentProcessName", "string", "QSTRING");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("process_host_ip", "int", "IPv4");


INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="scanID"), 5);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="processID"), 6);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="creationDate"), 7);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="terminationDate"), 8);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="parentProcessID"), 9);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="handle"), 10);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="processName"), 11);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="executablePath"), 12);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="process_host_ip"), 13);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="OSName"), 14);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="PROCESS"), (SELECT id FROM fields WHERE field="parentProcessName"), 15);

""" % class_num
	f = open('PROCESS_db_setup.sql','w')
	f.write(sql_file)
	f.close()
	
def usage():
		print "Usage: OpenVAStoELSA.py [-i host_file | --host_file=host_file] [-t max_thread_count | --thread_count=max_thread_count] [-e class-num| --elsa-class-num=class-num] [-s | --create-sql-file] [-h | --help]"
def main():

	letters = 'i:t:e:l:u:p:sh'
	keywords = ['input-file=', 'thread-count=', 'elsa-class-num=', 'elsa-server-ip=', 'user=', 'password=', 'create-sql-file', 'help' ]
	try:
		opts, extraparams = getopt.getopt(sys.argv[1:], letters, keywords)
	except getopt.GetoptError, err:
		print str(err)
		usage()
		sys.exit()
	in_file = 'hosts.txt'
	out_file = 'process.log'
	elsa_class = 10004
	make_sql_file = False
	maxthreads = 12
	elsa_server_ip = '192.168.1.1'
	user = 'test'
	password = 'test'
	
	for o,p in opts:
	  if o in ['-i','--host-file']:
		 in_file = p
	  elif o in ['-t','--thread_count']:
		maxthreads = int(p)
	  elif o in ['-e','--elsa-class-num']:
		 elsa_class = p
	  elif o in ['-l','--elsa-server-ip']:
		 elsa_server_ip = p
	  elif o in ['-u','--user']:
		 user = p
	  elif o in ['-p','--password']:
		 password = p
	  elif o in ['-h', '--help']:
		 usage()
		 sys.exit()
	  elif o in ['-s', '--create-sql-file']:
			make_sql_file = True
	
	if (len(sys.argv) < 2):
		usage()
		sys.exit()
	
	try:
		with open(in_file) as f: pass
	except IOError as e:
		print "Input file does not exist. Exiting."
		sys.exit()
	
	
	if make_sql_file == True:
		create_sql_file(elsa_class)


	#read hosts file
	f = open(in_file)
	hosts = f.readlines()
	f.close()
	
	#read scanID file
	try:
		f = open('scanID.txt', 'r')
		s = f.read()
		id = int(s.rstrip())
		f.close()
		f = open('scanID.txt', 'w')
		f.write(str(id+1))
		f.close()
	except IOError as e:
		print "I/O error({0}): {1}".format(e.errno, e.strerror)
		f = open('scanID.txt', 'w')
		f.write('101')
		f.close()
	except ValueError:
		print "Could not convert data to an integer."
	except:
		print "Unexpected error:", sys.exc_info()[0]
		raise
		
	#Set the max number of threads, defaults to 12, can be set in script
	threads_sem = threading.Semaphore(maxthreads)
	
	print "User: " + user
	print "Password: " + password.encode('string-escape')
	#print elsa_server_ip
	for host in hosts:
		threads_sem.acquire()
		pg = ProcessGetter(time.time(), id, host.rstrip(),user,password.encode('string-escape'),elsa_server_ip)
		pg.start()
		threads_sem.release()

		
if __name__ == "__main__":
	main()

