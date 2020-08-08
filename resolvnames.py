#!/usr/bin/env python3

#resolvename.py a script for resolving names from sqlite databses created by the log analysis toolkit
#by changing the dbFile from memory to a filename you can maintain persistance between runs
#Joe McManus joe@cert.org
#version 0.1  2011/04/12
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

import socket
from sqlite3 import * 
import platform
import os
import re
import sys
import time
from urllib.parse import urlparse
from time import mktime, gmtime, strftime
import shlex
import pdb 

if platform.python_version() < "3.0.0": 
	print("ERROR: Python 3.0 or greater is required for this to run. Sorry")
	sys.exit()

def printUsage(error):
	print("ERROR: " + error)
	print("USAGE: " + sys.argv[0] + " DATABASE_NAME query")
	sys.exit()

logFile="query-output.csv"

def openLogFile(logFile):
	fh = open(logFile, 'w') 
	return fh

def dbFileCheck(dbFile):
	if os.path.isfile(dbFile):
		db = connect(dbFile)
		curs=db.cursor()
	else:
		printUsage("Database File does not exist")
	return curs, db

def resolveNames(curs, query, fh):
	curs.execute(query)
	for row in curs:
		try: 
			nameTuple = socket.gethostbyaddr(row[0])
			name=nameTuple[0]
		except:
			name = "unresolvable"

		print(row[0] + "," + name)
		fh.write(row[0] + "," + name + "\n")
def commandLineOptions():
	if len(sys.argv) < 3:
		printUsage("Must supply database file name and query.")
	dbFile=sys.argv[1]
	query=sys.argv[2]
	return dbFile, query
	

cmdOpts=commandLineOptions()
dbFile=cmdOpts[0]
query=cmdOpts[1]
dbInfo=dbFileCheck(dbFile)
curs=dbInfo[0]
db=dbInfo[1]
fh=openLogFile(logFile)

#This will work on all Log Analysis ToolKit databases, so you can use destIP too.
#Go Crazy

#This query will resolve all names that went to your phpmyadmin page
#query="select DISTINCT(clientIP) FROM logData WHERE page LIKE '%phpmyadmin%'"

#This query will resolve all client nmes that went to sites like google.com
#query="select DISTINCT(clientip) FROM proxyData WHERE destip LIKE '%google.com%'"
resolveNames(curs, query, fh)

fh.close()
