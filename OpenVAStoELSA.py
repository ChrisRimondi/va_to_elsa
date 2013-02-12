#!/usr/bin/env python
#OpenVAStoELSA.py
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
# Order | Field     	| Notes
# 0     | timestamp 	|
#1      | host			|
#2      | program name	|
#3      | class			|
#4 		| msg			|
# i0 	| ip 			| right now same as host
# i1 	| port			|
# i2 	| cvss_base		|
# i3 	| open			|
# i4 	| open			|
# i5 	| open			|
# s0 	| protocol		|
# s1 	| oid 			|
# s2 	| vuln_desc		|
# s3 	| service		|
# s4 	| risk_factor	|
# s5 	| cve			|

import socket
import binascii
import time
import codecs
import struct
import locale
import glob
import sys
import getopt
import xml.etree.ElementTree as xml
import re

class OpenVasParser:
	"This clas will parse an OpenVAS XML file and create an object"
	
	def __init__(self, input_file):
		self.input_file = input_file
		self.tree = self.__importXML()
		self.root = self.tree.getroot()
		self.issueList = self.__createIssuesList()
		self.portList = self.__createPortsList()
		
	def displayInputFileName(self):
		print self.input_file
		
	def __importXML(self):
		#Parse XML directly from the file path
		return xml.parse(self.input_file)
		
	def __createIssuesList(self):
		"Returns a list of dictionaries for each issue in the report"
		issuesList = [];
		for result in self.root.iter('result'):
			issueDict = {};
			if result.find('host') is not None:
				issueDict['host'] = unicode(result.find('host').text)
				issueDict['full_text'] = unicode(result.find('host').text)
				#print issueDict['host']
			for nvt in result.iter('nvt'):
				issueDict['oid'] = unicode(nvt.attrib['oid'])
				issueDict['full_text'] += ' | ' + unicode(nvt.attrib['oid'])
				for child in nvt:
					issueDict[child.tag] = unicode(child.text)
					issueDict['full_text'] += ' | ' + unicode(child.text)
			
			if result.find('description') is not None:
				issueDict['description'] = unicode(result.find('description').text)
				issueDict['full_text'] += ' | ' + unicode(result.find('description').text)
			if issueDict:
				issuesList.append(issueDict)
		
		#for x in issuesList:
		#	print x['description']
		return issuesList
		
		
	
	def __createPortsList(self):
		"Returns a list of dictionaries for each ports in the report"
		portsList = [];
		for p in self.root.iter('ports'):
			for port in p:
				portDict = {};
				if port.text != 'general/tcp':
					d = self.parsePort(port.text)
					#print d['service']
					if port.find('host').text is not None: portDict['host'] = port.find('host').text
					if d != None: 
						portDict['service'] = d['service']
						portDict['port'] = d['port']
						portDict['protocol'] = d['protocol']
						portDict['full_text'] = portDict['host'] + ' | ' + portDict['service'] +' | ' +  portDict['port'] +' | ' +  portDict['protocol']
						portsList.append(portDict)
					
			
			
		return portsList
		
	def parsePort(self,string):
		fieldsDict={};
		portsParsed = re.search(r'(\S*\b)\s\((\d+)\/(\w+)',string)
		#portsParsed = re.search('(\S*)\s\((\d+)\/(\w+)',string)
		#print string
		if portsParsed:
			fieldsDict['service'] = unicode(portsParsed.group(1))
			fieldsDict['port'] = unicode(portsParsed.group(2))
			fieldsDict['protocol'] = unicode(portsParsed.group(3))
			#print fieldsDict
			return fieldsDict
		return None

		
	def getIssueStringCSVList(self):
		"Displays issue list in string CSV format"
		stringCSVList = []
		for issue in self.issueList:
			stringCSV = ''
			for key,value in issue.iteritems():
				stringCSV += unicode(value) + ','
			stringCSVList.append(unicode(stringCSV))
		return stringCSVList

class OpenVasLogger:
	"This clas will take in an object from OpenVasParser and log it to a flat file"
	
	def __init__(self, ov, elsa_class_num=10002):
		self.ov_parsed = ov
		self.elsa_class_num = elsa_class_num
		
	def createElsaLogList(self):
		"Creates a log in ELSA preferred format"
		#print self.ov_parsed
		logList = []
		for item in self.ov_parsed.issueList:
			if item['oid'] != '0':
				#print item['oid']
				fieldList = []
				# Timestamp is order 0
				fieldList.append(int(time.time()))
				# Host IP is order 1
				fieldList.append(unicode(struct.unpack('>L', socket.inet_aton(item['host']))[0])) #inet of host
				# Program Name is order 2
				#fieldList.append(unicode(binascii.crc32('OPENVAS') & 0xffffffff)) #crc32 of program name
				fieldList.append('OPENVAS')
				# Class ID is order 3
				fieldList.append(self.elsa_class_num) #class ID
				# Message is order 4
				fieldList.append(unicode(item['full_text'].replace('\t',' ').replace('\r',' ').replace('\n',' '))) #message value
				# IP is i0, right now same as host
				fieldList.append(item['host'])
				# Port is i1, None for Issues
				fieldList.append('None')
				# CVSS_base is i2
				fieldList.append(unicode(item['cvss_base']))
				# i3 - i5 are null
				fieldList.append('')
				fieldList.append('')
				fieldList.append('')
				# Protocol is s0, None for Issues
				fieldList.append('None')
				# OID is s1
				fieldList.append(unicode(item['oid']))
				# Vulnerability description (i.e. name) is s2
				fieldList.append(unicode(item['name']))
				# Service is s3, None for Issues
				fieldList.append('None')
				# Risk Factor is s4
				fieldList.append(unicode(item['risk_factor']))
				# CVE is s5
				fieldList.append(unicode(item['cve']))
				
				log = unicode('');
				#tab delimit fields
				for field in fieldList:
					log += unicode(field) + '	'
				logList.append(log + '\n')	
				
		for item in self.ov_parsed.portList:
				#print item['oid']
				fieldList = []
				# Timestamp is order 0
				fieldList.append(int(time.time()))
				# Host IP is order 1
				fieldList.append(unicode(struct.unpack('>L', socket.inet_aton(item['host']))[0])) #inet of host
				# Program Name is order 2
				#fieldList.append(unicode(binascii.crc32('OPENVAS') & 0xffffffff)) #crc32 of program name
				fieldList.append('OPENVAS')
				# Class ID is order 3
				fieldList.append(self.elsa_class_num) #class ID
				# Message is order 4
				fieldList.append(unicode(item['full_text'].replace('\t',' ').replace('\r',' ').replace('\n',' '))) #message value
				# IP is i0, right now same has host
				fieldList.append(item['host'])
				# Port is i1
				fieldList.append(item['port'])
				# CVSS_base is i2, None for ports
				fieldList.append('None')
				# i3 - i5 are null
				fieldList.append('')
				fieldList.append('')
				fieldList.append('')
				# Protocol is s0
				fieldList.append(item['protocol'])
				# OID is s1, None for ports
				fieldList.append('None')
				# Vulnerability description (i.e. name) is s2, None for ports
				fieldList.append('None')
				# Service is s3
				fieldList.append(item['service'])
				# Risk Factor is s4, None for ports
				fieldList.append('None')
				# CVE is s5, None for ports
				fieldList.append('None')
				
				log = unicode('');
				#tab delimit fields
				for field in fieldList:
					log += unicode(field) + '	'
				logList.append(log + '\n')	
		return logList
				
		
	def ovElsaLogToDisk(self,filename,format='utf-8'):
		"Opens filename and writes log to disk"
		f = open(filename,'w')
		for log in self.createElsaLogList():
			f.write(log.encode(format))
		f.close()

#-------------------------#
# Begin the main program. #
#-------------------------#
def create_sql_file(class_num):
	sql_file = """
use syslog;
INSERT INTO classes (id, class) VALUES (%s, "OPENVAS");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("cvss_base", "int", "NUMBER");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("oid", "string", "QSTRING");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("vuln_desc", "string", "QSTRING");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("risk_factor", "string", "QSTRING");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("cve", "string", "QSTRING");


INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="OPENVAS"), (SELECT id FROM fields WHERE field="ip"), 5);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="OPENVAS"), (SELECT id FROM fields WHERE field="port"), 6);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="OPENVAS"), (SELECT id FROM fields WHERE field="cvss_base"), 7);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="OPENVAS"), (SELECT id FROM fields WHERE field="proto"), 11);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="OPENVAS"), (SELECT id FROM fields WHERE field="oid"), 12);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="OPENVAS"), (SELECT id FROM fields WHERE field="vuln_desc"), 13);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="OPENVAS"), (SELECT id FROM fields WHERE field="service"), 14);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="OPENVAS"), (SELECT id FROM fields WHERE field="risk_factor"), 15);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="OPENVAS"), (SELECT id FROM fields WHERE field="cve"), 16);
""" % class_num
	f = open('openvas_db_setup.sql','w')
	f.write(sql_file)
	f.close()
	
def usage():
		print "Usage: OpenVAStoELSA.py [-i input_file | --input_file=input_file] [-o output_file | --output_file=output_file] [-e class-num| --elsa-class-num=class-num] [-s | --create-sql-file] [-h | --help]"
def main():

	letters = 'i:o:e:sh' #input_file, output_file, elsa_class_num respectively
	keywords = ['input-file=', 'output-file=', 'elsa-class-num=', 'create-sql-file', 'help' ]
	try:
		opts, extraparams = getopt.getopt(sys.argv[1:], letters, keywords)
	except getopt.GetoptError, err:
		print str(err)
		usage()
		sys.exit()
	in_file = 'openvas.xml'
	out_file = 'openvas.log'
	elsa_class = 10002
	make_sql_file = False
	
	for o,p in opts:
	  if o in ['-i','--input-file']:
		 in_file = p
	  elif o in ['-o','--output-file']:
		 out_file = p
	  elif o in ['-e','--elsa-class-num']:
		 elsa_class = p
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
	
	ov = OpenVasParser(in_file)
	logger = OpenVasLogger(ov,elsa_class)
	logger.ovElsaLogToDisk(out_file)
	if make_sql_file == True:
		create_sql_file(elsa_class)

if __name__ == "__main__":
	main()

