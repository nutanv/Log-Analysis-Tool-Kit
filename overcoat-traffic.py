#!/usr/bin/env python3
#overcoat-traffic.py a script for creating network traffic information out of proxy logs
#by changing the dbFile from memory to a filename you can maintain persistance between runs
#Joe McManus joe@cert.org
#version 0.2  2011/03/21
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
#dbFile="overcoat.db"
dbFile=":memory:"


def createDb(db):
	curs = db.cursor()
	curs.execute('''create table proxyData (id integer primary key, clientip text, destip text, time timestamp, duration int, bytesIn int, bytesOut int, direction text)''')
	db.commit()
	
def addRecord(db, id, clientIP, destIP, timestamp, duration, bytesIn, bytesOut, direction):
	curs= db.cursor()
	curs.execute("""INSERT INTO proxyData (id, clientip, destip, time, duration, bytesIn, bytesOut, direction) VALUES (?,?,?,?,?,?,?,?)""", (None, clientIP, destIP, timestamp, duration, bytesIn, bytesOut, direction))
	db.commit()

def bluecoatDetail(curs):
	print("Client IP |".rjust(18) \
                + "Dest IP |".rjust(44) \
                + "Direction |".rjust(14) \
		+ "# of Recs. |".rjust(12) \
                + "Bytes In |".rjust(12) \
                + "Bytes Out |".rjust(12) \
                + "Total Bytes |".rjust(12) )

	print("-" * 130)

	curs.execute("SELECT clientIP, destIP, SUM(bytesIn), SUM(bytesOut), (SUM(bytesIn)+ SUM(bytesOut)) as byteTotal,  COUNT(id) AS count FROM proxyData GROUP BY clientIP, destIP  order by byteTotal DESC")
	for row in curs:
		bytesIn=int(row[2])
		bytesOut=int(row[3])
		if bytesIn > bytesOut:
			direction="in"
		elif bytesOut > bytesIn:
			direction="out"
		else:
       			direction="=="		
		print(row[0].rjust(16) + " |" \
			+ row[1].rjust(42) + " |" \
			+ direction.rjust(12) + " |" \
			+ str(row[5]).rjust(10) + " |" \
			+ str(row[2]).rjust(10) + " |" \
			+ str(row[3]).rjust(10) + " |"\
			+ str(row[4]).rjust(12) )
	
def bluecoatSummary(curs):
	print("Client IP |".rjust(18) \
                + "Bytes In |".rjust(12) \
                + "Bytes Out |".rjust(12) \
                + "Total Bytes |".rjust(12) 
		+ "# of Hosts".rjust(12) )

	print("-" * 70)

	curs.execute("SELECT clientIP, SUM(bytesIn), SUM(bytesOut), (SUM(bytesIn)+ SUM(bytesOut)) as byteTotal, COUNT(DISTINCT(destIP)) AS count FROM proxyData GROUP BY clientIP order by byteTotal DESC")
	for row in curs:
		bytesIn=int(row[1])
		bytesOut=int(row[2])
		print(row[0].rjust(16) + " |" \
			+ str(row[1]).rjust(12) + " |" \
			+ str(row[2]).rjust(10) + " |" \
			+ str(row[3]).rjust(10) + " |" \
			+ str(row[4]).rjust(10) )


def squidDetail(curs):
	print("Client IP |".rjust(18) \
                + "Dest IP |".rjust(54) \
                + "Direction |".rjust(14) \
		+ "# of Recs. |".rjust(12) \
                + "Total Bytes |".rjust(12) )

	print("-" * 114)

	curs.execute("SELECT clientIP, destIP, SUM(bytesIn) AS bytes, direction, COUNT(id) AS count FROM proxyData GROUP BY clientIP, destIP  order by bytes DESC")
	for row in curs:
		print(row[0].rjust(16) + " |" \
			+ row[1].rjust(52) + " |" \
			+ row[3].rjust(12) + " |" \
			+ str(row[4]).rjust(10) + " |" \
			+ str(row[2]).rjust(12) )

def squidSummary(curs):
	print("Client IP |".rjust(18) \
                + "Bytes |".rjust(12) \
		+ "# of Hosts".rjust(12) )

	print("-" * 42)

	curs.execute("SELECT clientIP, SUM(bytesIn) AS bytes, COUNT(DISTINCT(destIP)) AS count FROM proxyData GROUP BY clientIP order by bytes DESC")
	for row in curs:
		print(row[0].rjust(16) + " |" \
			+ str(row[1]).rjust(12) + " |" \
			+ str(row[2]).rjust(10) )

def commandLineOptions():
	if len(sys.argv) < 4:
		print("ERROR: Must supply log file name, proxy type and report type.")
		print("USAGE: " + sys.argv[0] + "(bluecoat|squid) (detail|summary) LOG_FILE_NAME")
		sys.exit()

	#Check for a log file	
	logFile=sys.argv[3]
	if os.path.isfile(logFile):
		print("Logfile: " + logFile) 
	else:
		print("ERROR: Logfile " + logFile + " does not exist")
		sys.exit()

	#Check for log type
	if sys.argv[1] == "bluecoat":
		logType="bluecoat"
	elif sys.argv[1] == "squid":
		logType="squid"
	else: 
		print("ERROR: Invalid proxy format specified.")
		print("USAGE: " + sys.argv[0] + "(bluecoat|squid) LOG_FILE_NAME")
		sys.exit()

	if sys.argv[2] == "summary":
		reportType = "summary"
	elif sys.argv[2] == "detail": 
		reportType = "detail"
	else: 
		print("ERROR: Invalid report format specified.")
		print("USAGE: " + sys.argv[0] + "(bluecoat|squid) (summary|detail) LOG_FILE_NAME")
		sys.exit()

	return logType, logFile, reportType


def dbFileCheck(dbFile):
	#Check to see if the db file exists
	if os.path.isfile(dbFile):
		fileSize=os.path.getsize(dbFile)
		fileModTime=str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(dbFile))))
		print("Using SQLite DB file " + dbFile + ", bytes " + str(fileSize) + ", last modified " + fileModTime + ".")   
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
		
def importData(db, logFile, logType): 
	#Process file
	fh=open(logFile, 'r', encoding='iso-8859-1')

	print("Creating list of Connections.",)
	i=0
	proxyData=[]
	for line in fh: 
		#Check to see if the line looks right.
		if line[:1].isdigit():
			logEntry=shlex.split(line)
			if logType == "bluecoat":
				if len(logEntry) > 12:
					clientIP=logEntry[3]
					destIP=logEntry[15]
					timestamp=logEntry[0] + " " + logEntry[1]
					timestamp=time.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
					timestamp=time.mktime(timestamp)
					duration=logEntry[2]
					
					bytesIn=int(logEntry[22])
					bytesOut=int(logEntry[23])
					
					#Calculate the direction of traffic
					if bytesIn > bytesOut:
						direction="in"
					elif bytesIn < bytesOut:
						direction="out"
					else:
						direction="unknown"
					addRecord(db, id, clientIP, destIP, timestamp, duration, bytesIn, bytesOut, direction)
					i+=1
	
			if logType == "squid":
				if len(logEntry) > 8:
					clientIP=logEntry[2]
					peerinfo=urlparse(logEntry[6])
					destIP=peerinfo.hostname
					if destIP == None:
						destIP = "Unknown"
					timestamp=time.localtime(float(logEntry[0]))
					timestamp=time.mktime(timestamp)
					bytes=logEntry[4]
					noBytes=None
					duration=logEntry[1]
					if logEntry[5] == "GET":
						direction="in"
					elif logEntry[5] == "POST":
						direction="out"
					else:
						direction="unknown"
	
					addRecord(db, id, clientIP, destIP, timestamp, duration, bytes, noBytes, direction)
					i+=1

cmdOpts=commandLineOptions()
logType=cmdOpts[0]
logFile=cmdOpts[1]
reportType=cmdOpts[2]
dbInfo=dbFileCheck(dbFile)
curs=dbInfo[0]
db=dbInfo[1]

importData(db, logFile, logType)


if logType == "bluecoat" and reportType == "detail": 
	bluecoatDetail(curs)

if logType == "bluecoat" and reportType == "summary": 
	bluecoatSummary(curs)

if logType == "squid" and reportType == "detail": 
	squidDetail(curs)

if logType == "squid" and reportType == "summary": 
	squidSummary(curs)
