#!/usr/bin/env python3

#logminer.py a script for creating network traffic information out of web server logs
#by changing the dbFile from memory to a filename you can maintain persistance between runs
#Joe McManus joe@cert.org
#version 0.1  2011/03/10
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


from sqlite3 import * 
import platform
import os
import re
import sys
import time
from urllib.parse import urlparse
from time import mktime, gmtime, strftime
import shlex
import re
import pdb 


if platform.python_version() < "3.0.0": 
	print("ERROR: Python 3.0 or greater is required for this to run. Sorry")
	sys.exit()

#You can use a file for persistence or run it out of memory
#dbFile="logminer.db"
dbFile=":memory:"


def createDb(db):
	curs = db.cursor()
	curs.execute('''create table logData (id integer primary key, clientip text, time timestamp, bytesIn int, bytesOut int,  page text)''')
	db.commit()
	
def addRecord(db, id, clientIP, timestamp, bytesIn, bytesOut, page ):
	curs = db.cursor()
	curs.execute("""INSERT INTO logData (id, clientip, time, bytesIn, bytesOut, page) VALUES (?,?,?,?,?,?)""", (None, clientIP, timestamp, bytesIn, bytesOut, page))
	db.commit()

def pageDiffs(curs):
	#Get the last day in the database
	curs.execute("select distinct(strftime('%Y-%m-%d', time, 'unixepoch'))  from logData order by time desc limit 1")
	for row in curs:
		lastDate=row[0]
	#Get the files present in the last week
	currentUrl=[]
	previousUrl=[]
	curs.execute("""select  distinct (strftime('%Y-%m-%d', time, 'unixepoch')) as logTime, page from logData where logTime between date(?, '-7 days' ) and date(?)""", (lastDate, lastDate))
	for row in curs:
		currentUrl.append(row[1])
	currentTotal=len(currentUrl)
	print("Current Week Total: " + str(currentTotal))
	
	curs.execute("""select  distinct (strftime('%Y-%m-%d', time, 'unixepoch')) as logTime, page from logData where logTime between date(?, '-14 days' ) and date(?, '-8 days')""", (lastDate, lastDate))
	i=0
	for row in curs:
		previousUrl.append(row[1])
	previousTotal=len(previousUrl)
	print("Previous Week Total: " + str(previousTotal))
	
	print("-"* 70)
	print("New files in the current week")
	print("-"* 70)
	currentDiffs=list(set(currentUrl).difference(set(previousUrl)))	
	for url in currentDiffs:
		print(url)
	
	print("-"* 70)
	print("Files in the previous week not present in the most current week")
	print("-"* 70)
	previousDiffs=list(set(previousUrl).difference(set(currentUrl)))	
	for url in previousDiffs:
		print(url)
	

def trafficSummary(curs, logType):
	print("Client IP |".rjust(18) + "Bytes |".rjust(12) )
	print("-" * 42)

	curs.execute("select sum(bytesOut) as totalBytes, clientIP from logData group by clientip order by totalBytes Desc limit 20")
	for row in curs:
		print(str(row[1]).rjust(16) + " |" + str(row[0]).rjust(12) )


	print("Client IP |".rjust(18)  + "# of Pages".rjust(12) )
	print("-" * 42)
	curs.execute(" select count(page) as totalPages, clientIP from logData group by clientip order by totalPages Desc limit 20 ")
	for row in curs:
		print(row[1].rjust(16) + " |" + str(row[0]).rjust(10) )


	print("Page |".rjust(58)  + "# of Bytes".rjust(12) )
	print("-" * 72)
	curs.execute(" select sum(bytesOut) as totalBytes, page from logData group by page order by totalBytes Desc limit 20")
	for row in curs:
		print(row[1].rjust(56) + " |" + str(row[0]).rjust(10) )

	if logType == "iis":
		print("Page |".rjust(58)  + "# of Bytes In".rjust(12) )
		print("-" * 72)
		curs.execute(" select sum(bytesIn) as totalBytes, page from logData group by page order by totalBytes Desc limit 20")
		for row in curs:
			print(row[1].rjust(56) + " |"  + str(row[0]).rjust(10) )

def importData(db, logFile, logType):
	fh=open(logFile, 'r', encoding='iso-8859-1')
	print("Creating list of Connections.",)
	i=0
	logData=[]
	for line in fh: 
		#Check to see if the line looks right.
		if line[:1].isdigit():
			try:
				logEntry=shlex.split(line)
			except:
				print('ERROR: Unable to parse line ' + str(i) + " skipping.")
	
			if logType == "apache":
				if len(logEntry) > 8:
					returnCode = logEntry[6]
					if returnCode != "404":
						clientIP=logEntry[0]
						timestamp=time.strptime(logEntry[3], "[%d/%b/%Y:%H:%M:%S")
						timestamp=time.mktime(timestamp)
						bytesOut=logEntry[7]
						page=shlex.split(str(urlparse(logEntry[5]).path))
						addRecord(db, id, clientIP, timestamp, None, bytesOut, page[1])
			if logType == "iis":
				if len(logEntry) > 8:
					returnCode = logEntry[14]
					if returnCode != "404":
						clientIP=logEntry[9]
						timestamp=time.strptime(logEntry[0] + " " + logEntry[1], "%Y-%m-%d %H:%M:%S")
						timestamp=time.mktime(timestamp)
						bytesOut=logEntry[17]
						bytesIn=logEntry[18]
						page=logEntry[5]
						addRecord(db, id, clientIP, timestamp, bytesIn, bytesOut, page)
		i += 1
				
def logFileCheck():
	if len(sys.argv) < 4:
		print("ERROR: Must supply log file name, log type and report type.")
		print("USAGE: " + sys.argv[0] + "(apache|iis) (pagediff|traffic) LOG_FILE_NAME")
		sys.exit()
	logFile=sys.argv[3]
	if logFile != "history":
		if os.path.isfile(logFile):
			print("Logfile: " + logFile) 
		else:
			print("ERROR: Logfile " + logFile + " does not exist")
			sys.exit()
	return logFile

def dbFileCheck(dbFile, logFile):
	if os.path.isfile(dbFile) and logFile == "history":
			db = connect(dbFile)
			curs=db.cursor()
	elif os.path.isfile(dbFile):
		fileAction= input("Database file exists. Erase or Append (E/A): ?")
		if  fileAction == "e" or fileAction == "E":
			os.remove(dbFile)
			db = connect(dbFile)
			curs=db.cursor()
			createDb(db)
		else: 
			db = connect(dbFile)
			curs=db.cursor()
	else:
		db = connect(dbFile)
		curs=db.cursor()
		createDb(db)
	return curs, db
	
def commandLineOptions():
	if len(sys.argv) < 4:
		print("ERROR: Must supply log file name, log type and report type.")
		print("USAGE: " + sys.argv[0] + "(apache|iis) (pagediff|traffic) LOG_FILE_NAME")
		sys.exit()
	logFile=sys.argv[3]
	if logFile != "history":
		if os.path.isfile(logFile):
			print("Logfile: " + logFile) 
		else:
			print("ERROR: Logfile " + logFile + " does not exist")
			sys.exit()
	if sys.argv[1] == "apache":
		logType="apache"
	elif sys.argv[1] == "iis":
		logType="iis"
	else: 
		print("ERROR: Invalid log format specified.")
		print("USAGE: " + sys.argv[0] + "(apache|iis) LOG_FILE_NAME")
		sys.exit()

	if sys.argv[2] == "traffic":
		reportType = "traffic"
	elif sys.argv[2] == "pagediff": 
		reportType = "pagediff"
	else: 
		print("ERROR: Invalid report format specified.")
		print("USAGE: " + sys.argv[0] + "(apache|iis) (pagediff|traffic) LOG_FILE_NAME")
		sys.exit()
	return logType, reportType, logFile

cmdOpts=commandLineOptions()
logType=cmdOpts[0]
reportType=cmdOpts[1]
logFile=cmdOpts[2]
dbInfo=dbFileCheck(dbFile, logFile)
curs=dbInfo[0]
db=dbInfo[1]

if logFile != "history": 
	importData(db, logFile, logType)

if reportType == "pagediff":
	pageDiffs(curs)
if reportType == "traffic":
	trafficSummary(curs, logType)
