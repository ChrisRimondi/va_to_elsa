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
import logging
from logging.handlers import SysLogHandler

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

class NessusSyslogger:
	"This clas will take in an object from NessusParser and log it to syslog"
	
	def __init__(self, np, elsa_class_num=10003):
		self.np_parsed = np
		self.elsa_class_num = elsa_class_num
		#init syslog capabilities
		self.logger = logging.getLogger()
		self.logger.setLevel(logging.INFO)
		self.syslog = SysLogHandler(address=('192.168.1.116', 514))
		self.formatter = logging.Formatter('VA: %(message)s')
		self.syslog.setFormatter(self.formatter)
		self.logger.addHandler(self.syslog)
		
	def toSyslog(self):
		for item in self.np_parsed.issueList:
			#print item['full_text']
			self.logger.info(item['full_text'])
		
	
		

#-------------------------#
# Begin the main program. #
#-------------------------#
def create_sql_file():
	sql_file = """
use syslog;
INSERT INTO classes (id, class) VALUES (10201, "VULNERABILITY");
INSERT INTO classes (id, class) VALUES (10202, "ASSET_ATTRIBUTE");
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

"""
	f = open('va_db_setup.sql','w')
	f.write(sql_file)
	f.close()
	
def usage():
		print "Usage: VAtoELSA.py [-i input_file | --input_file=input_file] [-s | --create-sql-file] [-h | --help]"
def main():

	letters = 'i:sh' #input_file, output_file, elsa_class_num respectively
	keywords = ['input-file=', 'create-sql-file', 'help' ]
	try:
		opts, extraparams = getopt.getopt(sys.argv[1:], letters, keywords)
	except getopt.GetoptError, err:
		print str(err)
		usage()
		sys.exit()
	in_file = 'report.nessus'
	make_sql_file = False
	
	for o,p in opts:
	  if o in ['-i','--input-file']:
		 in_file = p
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
	syslogger = NessusSyslogger(np)
	if make_sql_file == True:
		create_sql_file()
	syslogger.toSyslog()

if __name__ == "__main__":
	main()

