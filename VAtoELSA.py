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

# ASSET_ATTRIBUTE
# ELSA    Field Order Information
# Order | Field     	| DB Order
# 0     | timestamp 	|
#1      | host			|
#2      | program name	|
#3      | class			|
#4 		| msg			| 
# i0    | srcip			| 5
# i1 	| srcport		| 6
# i2 	| proto			| 7
# i3 	| macb			| 11
# s1 	| hostname		| 12
# s2 	| operating_system		| 13
# s3 	| service		| 14
# s4 	| desc			| 15
# s5 	| notes			| 16

# VULNERABILITY
# ELSA    Field Order Information
# Order | Field     	| DB Order
# 0     | timestamp 	|
#1      | host			|
#2      | program name	|
#3      | class			|
#4 		| msg			| 
# i0    | srcip			| 5
# i1 	| srcport		| 6
# i2 	| severity		| 7
# i3 	| proto			| 8
# s1 	| rule			| 12
# s2 	| desc			| 13
# s3 	| service		| 14
# s4 	| cve			| 15


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

class NessusParser:
	"This clas will parse an Nessus v2 XML file and create an object"
	
	def __init__(self, input_file):
		self.input_file = input_file
		self.tree = self.__importXML()
		self.root = self.tree.getroot()
		self.issueList = self.__createIssuesList()
		
	def displayInputFileName(self):
		print self.input_file
		
	def __importXML(self):
		#Parse XML directly from the file path
		return xml.parse(self.input_file)
		
	def __createIssuesList(self):
		"Returns a list of dictionaries for each issue in the report"
		list_issue = [];
		#Nessus root node only has 2 children. policy and report, we grab report here
		report = self.root.getchildren()[1]
		#each child node of report is a report host - rh
		for rh in report:
	
			ip = rh.attrib['name']
			#print rh.tag
			#iterate through attributes of ReportHost tags
			for tag in rh.getchildren():
				dict_item = {}
				dict_item['ip'] = ip
				dict_item['full_text'] = "IP: " + ip
				#print tag.tag
				if tag.tag == 'HostProperties':
					for child in tag.getchildren():
						if child.attrib['name'] == 'HOST_END':
							dict_item['time'] = child.text
						if child.attrib['name'] == 'operating-system':
							dict_item['operating-system'] = child.text
							dict_item['full_text'] += " | OS: " + child.text
						if child.attrib['name'] == 'mac-address':
							dict_item['mac-address'] = child.text
							dict_item['full_text'] += " | MAC: " + child.text
						if child.attrib['name'] == 'host-fqdn':
							dict_item['operating-system'] = child.text
							dict_item['full_text'] += " | FQDN: " + child.text
					#print dict_item
				elif tag.tag == 'ReportItem':
					#print tag.tag
					if tag.attrib['port']:
						dict_item['port'] = tag.attrib['port']
						dict_item['full_text'] += " | Port: " + tag.attrib['port']
					if tag.attrib['svc_name']:
						dict_item['svc_name'] = tag.attrib['svc_name']
						dict_item['full_text'] += " | SVC: " + tag.attrib['svc_name']
					if tag.attrib['protocol']:
						dict_item['protocol'] = tag.attrib['protocol']
						dict_item['full_text'] += " | Protocol: " + tag.attrib['protocol']
					if tag.attrib['severity']:
						dict_item['severity'] = tag.attrib['severity']
						dict_item['full_text'] += " | Severity: " + tag.attrib['severity']
					if tag.attrib['pluginID']:
						dict_item['pluginID'] = tag.attrib['pluginID']
						dict_item['full_text'] += " | NID: " + tag.attrib['pluginID']
					if tag.attrib['pluginName']:
						dict_item['pluginName'] = tag.attrib['pluginName']
						dict_item['full_text'] += " | Plugin Name: " + tag.attrib['pluginName']
					if tag.attrib['pluginFamily']:
						dict_item['pluginFamily'] = tag.attrib['pluginFamily']
						dict_item['full_text'] += " | Plugin Family: " + tag.attrib['pluginFamily']
					#Iterate through child tags and texts of ReportItems
					#These are necessary because there can be multiple of these tags
					dict_item['cve'] = ''
					dict_item['bid'] = ''
					dict_item['xref'] = ''
					#print dict_item
					for child in tag.getchildren():
						#print child.tag
						if child.tag == 'solution':
							dict_item[child.tag] = child.text
						if child.tag == 'risk_factor':
							dict_item[child.tag] = child.text
							dict_item['full_text'] += " | Risk Factor: " + child.text
						if child.tag == 'description':
							dict_item[child.tag] = child.text
						if child.tag == 'synopsis':
							dict_item[child.tag] = child.text
							dict_item['full_text'] += " | Synopsis: " + child.text
						if child.tag == 'plugin_output':
							dict_item[child.tag] = child.text
						if child.tag == 'plugin_version':
							dict_item[child.tag] = child.text
							dict_item['full_text'] += " | Plugin Version: " + child.text
						if child.tag == 'see_also':
							dict_item[child.tag] = child.text
							dict_item['full_text'] += " | See also: " + child.text
						if child.tag == 'xref':
							dict_item[child.tag] += child.text + ','
							dict_item['full_text'] += " | xref: " + child.text
						if child.tag == 'bid':
							dict_item[child.tag] += child.text + ','
							dict_item['full_text'] += " | bid: " + child.text
						if child.tag == 'cve':
							dict_item[child.tag] += child.text + ','
							dict_item['full_text'] += " | CVE: " + child.text
						if child.tag == 'cvss_base_score':
							dict_item[child.tag] = float(child.text)
							dict_item['full_text'] += " | CVSS Base Score: " + child.text
						if child.tag == 'cvss_temporal_score':
							dict_item[child.tag] = float(child.text)
							dict_item['full_text'] += " | CVSS Temporal Score: " + child.text
						if child.tag == 'cvss_vector':
							dict_item[child.tag] = child.text
							dict_item['full_text'] += " | CVSS Vector: " + child.text
						if child.tag == 'exploit_available':
							if child.text == 'true':
								dict_item[child.tag] = 1
							else:
								dict_item[child.tag] = 0
							dict_item['full_text'] += " | Public Exploit Available: " + child.text
						if child.tag == 'plugin_modification_date':
							dict_item[child.tag] = child.text
							dict_item['full_text'] += " | Plugin Modification Date: " + child.text
						if child.tag == 'plugin_type':
							dict_item[child.tag] = child.text
							dict_item['full_text'] += " | Plugin Type: " + child.text
					#I am excluding longer fields in 'full_text' because they would be better served as a reference outside of the log, i.e. solution & description
					list_issue.append(dict_item)
		
		return list_issue

class NessusLogger:
	"This clas will take in an object from NessusParser and log it to a flat file"
	
	def __init__(self, np, elsa_class_num=10003):
		self.np_parsed = np
		self.elsa_class_num = elsa_class_num
		
	def createElsaLogList(self):
		"Creates a log in ELSA preferred format"
		logList = []
		#For reference comprehensive list of keys. Note:All issues do not contain all keys
		#dict_keys(['protocol', 'cvss_base_score', 'ip', 'risk_factor', 'port', 'xref', 'severity', 'synopsis', 'plugin_output', 'pluginID', 'svc_name', 'description', 'see_also', 'bid', 'plugin_modification_date', 'cvss_vector', 'plugin_version', 'solution', 'pluginName', 'cve', 'pluginFamily', 'plugin_type'])
		for item in self.np_parsed.issueList:
			#print item['oid']
			fieldList = []
			# Timestamp is order 0
			fieldList.append(int(time.time()))
			# Host IP is order 1
			fieldList.append(unicode(struct.unpack('>L', socket.inet_aton(item['ip']))[0])) #inet of host
			# Program Name is order 2
			#fieldList.append(unicode(binascii.crc32('NESSUS') & 0xffffffff)) #crc32 of program name
			fieldList.append('NESSUS')
			# Class ID is order 3
			fieldList.append(self.elsa_class_num) #class ID
			# Message is order 4
			fieldList.append(unicode(item['full_text'].replace('\t',' ').replace('\r',' ').replace('\n',' '))) #message value
			# i0 is exploit available 1 for true 0 for false
			if 'exploit_available' in item:
				fieldList.append(item['exploit_available'])
			else:
				fieldList.append(0)
			# Port is i1, None for Issues
			fieldList.append(item['port'])
			# CVSS_base is x10 to compensate for integer field
			if 'cvss_base_score' in item: 
				fieldList.append(unicode(item['cvss_base_score']*10))
			else:
				fieldList.append('No CVSS Base Score')
			if 'cvss_temporal_score' in item: 
				fieldList.append(unicode(item['cvss_temporal_score']*10))
			else:
				fieldList.append('No CVSS Temporal Score')
			if 'severity' in item:
				fieldList.append(item['severity'])
			else:
				fieldList.append('No Severity')
			fieldList.append('NO FIELD')
			#fieldList.append('')
			# Protocol is s0, 
			fieldList.append(item['protocol'])
			# NID is s1 pluginID
			fieldList.append(unicode(item['pluginID']))
			# Vulnerability description (i.e. synopsis) is s2
			if 'synopsis' in item:
				fieldList.append(unicode(item['synopsis']))
			else:
				fieldList.append('No Vulnerability Description')
			# Service is s3
			fieldList.append(item['svc_name'])
			# Risk Factor is s4
			if 'risk_factor' in item:
				fieldList.append(unicode(item['risk_factor']))
			else:
				fieldList.append('No Risk Factor')
			# CVE is s5
			if 'cve' in item:
				fieldList.append(unicode(item['cve']))
			else:
				fieldList.append('No CVE')
			
			log = unicode('');
			#tab delimit fields
			for field in fieldList:
				log += unicode(field).replace('\t',' ').replace('\r',' ').replace('\n',' ') + '	'
			logList.append(log + '\n')	
				
			
		return logList
				
		
	def npElsaLogToDisk(self,filename,format='utf-8'):
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
INSERT INTO classes (id, class) VALUES (10201, "VULNERABILITY");
INSERT INTO classes (id, class) VALUES (10201, "ASSET_ATTRIBUTE");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("operating_system", "string", "QSTRING");
INSERT INTO fields (field, field_type, pattern_type) VALUES ("cve", "string", "QSTRING");

INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="ASSET_ATTRIBUTE"), (SELECT id FROM fields WHERE field="srcip"), 5);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="ASSET_ATTRIBUTE"), (SELECT id FROM fields WHERE field="srcport"), 6);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="ASSET_ATTRIBUTE"), (SELECT id FROM fields WHERE field="proto"), 7);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="ASSET_ATTRIBUTE"), (SELECT id FROM fields WHERE field="macb"), 11);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="ASSET_ATTRIBUTE"), (SELECT id FROM fields WHERE field="hostname"), 12);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="ASSET_ATTRIBUTE"), (SELECT id FROM fields WHERE field="operating_system"), 13);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="ASSET_ATTRIBUTE"), (SELECT id FROM fields WHERE field="service"), 14);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="ASSET_ATTRIBUTE"), (SELECT id FROM fields WHERE field="desc"), 15);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="ASSET_ATTRIBUTE"), (SELECT id FROM fields WHERE field="notes"), 15);


INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="VULNERABILITY"), (SELECT id FROM fields WHERE field="srcip"), 5);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="VULNERABILITY"), (SELECT id FROM fields WHERE field="srcport"), 6);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="VULNERABILITY"), (SELECT id FROM fields WHERE field="severity"), 7);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="VULNERABILITY"), (SELECT id FROM fields WHERE field="proto"), 8);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="VULNERABILITY"), (SELECT id FROM fields WHERE field="rule"), 11);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="VULNERABILITY"), (SELECT id FROM fields WHERE field="desc"), 12);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="VULNERABILITY"), (SELECT id FROM fields WHERE field="service"), 13);
INSERT INTO fields_classes_map (class_id, field_id, field_order) VALUES ((SELECT id FROM classes WHERE class="VULNERABILITY"), (SELECT id FROM fields WHERE field="cve"), 14);

""" % class_num
	f = open('nessus_db_setup.sql','w')
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
	in_file = 'report.nessus'
	out_file = 'nessus.log'
	elsa_class = 10003
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
	
	np = NessusParser(in_file)
	logger = NessusLogger(np,elsa_class)
	logger.npElsaLogToDisk(out_file)
	if make_sql_file == True:
		create_sql_file(elsa_class)

if __name__ == "__main__":
	main()

