#!/usr/bin/env python3

#loginspector.py a script for SQLi and XSS attempts in web server logs
#Joe McManus joe@cert.org
#version 0.2  2011/04/11
#Copyright (C) 2011 Joe McManus
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.


import platform
import os
import re
import sys
import shlex
try: 
	from urllib.parse import urlparse
except: 
	print("ERROR: URLParse is not installed, please install and retry.")
	sys.exit()


if platform.python_version() < "3.0.0": 
	print("ERROR: Python 3.0 or greater is required for this to run. Sorry")
	sys.exit()


def processData(logFile, logType):
	fh=open(logFile, 'r', encoding='iso-8859-1')
	print("Parsing logfile")
	print("Alert Type |".rjust(15) + "Client IP |".rjust(18) + "URL".rjust(10))
	print("-" * 50)
	i=0
	for line in fh: 
		#Check to see if the line looks right.
		if line[:1].isdigit():
			try:
				logEntry=shlex.split(line)
			except:
				print('ERROR: Unable to parse line ' + str(i) + " skipping.")
			if logType == "apache":
				if len(logEntry) > 7:
					clientIP=logEntry[0]
					page=urlparse(logEntry[5])
					path=shlex.split(page.path)
					sqlCheck(path[1], page.query, clientIP)
			if logType == "iis":
				if len(logEntry) > 8:
					clientIP=logEntry[9]
					path=logEntry[5]
					query=logEntry[6]
					sqlCheck(path, query, clientIP)
			if logType == "iis-short":
				if len(logEntry) > 8:
					clientIP=logEntry[8]
					path=logEntry[4]
					query=logEntry[5]
					#Clean hosts
					regex=re.compile('56\.207\.116\.10|56\.207\.86\.59|56\.207\.116\.16|56\.88\.24\.18|74\.34\.20\.57')
					if not regex.search(clientIP):
						if query != "page=moveupdate": 
							sqlCheck(path, query, clientIP)
		i+=1
	print("Imported: " + i + " Records.")
				
def sqlCheck(path, query, clientIP):
	#Clear Text SQL injection test, will create false positives. 
	regex=re.compile('drop|delete|truncate|update|insert|select|declare|union|create|concat', re.IGNORECASE)
	if regex.search(query):
		print ("Clear SQL |".rjust(15) +  clientIP.rjust(16) + " | " + query)

	#look for single quote, = and --
	regex=re.compile('((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))|\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))', re.IGNORECASE)
	if regex.search(query):
		print ("SQLi |".rjust(15) +  clientIP.rjust(16) + " | " + query)
	
	#look for MSExec
	regex=re.compile('exec(\s|\+)+(s|x)p\w+', re.IGNORECASE)
	if regex.search(query):
		print ("MSSQL Exec |".rjust(15) +  clientIP.rjust(16) + " | " + query)

	#look for XSS
	regex=re.compile('((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)|((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)', re.IGNORECASE)
	if regex.search(query):
		print ("XSS |".rjust(15) +  clientIP.rjust(16) + " | " + query)


def logFileCheck():
	logFile=sys.argv[2]
	if os.path.isfile(logFile):
		print("Logfile: " + logFile) 
	else:
		print("ERROR: Logfile " + logFile + " does not exist")
		sys.exit()
	return logFile

def commandLineOptions():
	if len(sys.argv) < 2:
		print("ERROR: Must supply log type and log file name.")
		print("USAGE: " + sys.argv[0] + " (apache|iis) LOG_FILE_NAME")
		sys.exit()
	if sys.argv[1] == "apache":
		logType="apache"
	if sys.argv[1] == "iis-short":
		logType="iis-short"
	elif sys.argv[1] == "iis":
		logType="iis"
	else: 
		print("ERROR: Invalid log format specified.")
		print("USAGE: " + sys.argv[0] + " (apache|iis) LOG_FILE_NAME")
		sys.exit()
	return logType

logType=commandLineOptions()
logFile=logFileCheck()
processData(logFile, logType)
