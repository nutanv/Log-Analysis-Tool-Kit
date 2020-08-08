#!/usr/bin/env python3
#overcoat.py a script for detecting beaconing in proxy logs
#by changing the dbFile from memory to a filename you can maintain persistance between runs
#Joe McManus joe@cert.org
#version 0.5  2011/03/21
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
try: 
	import numpy
except: 
	print("ERROR: Numpy is not installed, please install and retry.")



if platform.python_version() < "3.0.0": 
	print("ERROR: Python 3.0 or greater is required for this to run. Sorry")
	sys.exit()

#You can use a file for persistence or run it out of memory
#dbFile="overcoat.db"
dbFile=":memory:"


def createDb(db):
	#This creates the SQLite DB, one table for raw data and one for the results
	curs = db.cursor()
	curs.execute('''create table proxyData (id integer primary key, clientip text, destip text, time timestamp, bytesDiff int, contentType int)''')
	db.commit()
	curs.execute('''create table timeData (id integer primary key, clientip text, destip text, mean int, stdDev int, count int, beaconScore int)''')
	db.commit()
	
def addRecord(db, id, clientIP, destIP, timestamp, bytes, content):
	#Add a record to the raw table
	curs= db.cursor()
	curs.execute("""INSERT INTO proxyData (id, clientip, destip, time, bytesDiff, contentType) VALUES (?,?,?,?,?,?)""", (None, clientIP, destIP, timestamp, bytes, content ))
	db.commit()

def addTimeRecord(db, id, clientIP, destIP, mean, stdDev, count, score):
	#Add a record to the timeData DB, which is what the results go in	
	curs= db.cursor()
	curs.execute("""INSERT INTO timeData (id, clientip, destip, mean, stdDev, count, beaconScore) VALUES (?,?,?,?,?,?,?)""", (None, clientIP, destIP, mean, stdDev, count, score))
	db.commit()

def ipCheck(ip_str):
	pattern = r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
	if re.match(pattern, ip_str):
		return True
	else:
		return False

def commandLineOptions():
	if len(sys.argv) < 3:
		print("ERROR: Must supply log file name and proxy type.")
		print("USAGE: " + sys.argv[0] + "(bluecoat|squid) LOG_FILE_NAME")
		sys.exit()

	#Check to see if the logfile exists
	logFile=sys.argv[2]
	if os.path.isfile(logFile):
		print("Logfile: " + logFile) 
	else:
		print("ERROR: Logfile " + logFile + " does not exist")
		sys.exit()
	if sys.argv[1] == "bluecoat":
		logType="bluecoat"
	elif sys.argv[1] == "squid":
		logType="squid"
	else: 
		print("ERROR: Invalid proxy format specified.")
		print("USAGE: " + sys.argv[0] + "(bluecoat|squid) LOG_FILE_NAME")
		sys.exit()
	return logType, logFile
	

	

def dbFileCheck(dbFile):
	#Check to see if the db file exist
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
			#So we are appending to the database, now lets delete the old ProxyData table
			curs.execute("delete from proxyData")
			db.commit()
	else:
		db = connect(dbFile)
		curs=db.cursor()
		createDb(db)
	return curs, db
		

def importData(db, logFile, logType):
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
					
					#Calculate the diffence in uploaded/downloaded bytes
					bytesDiff=abs(int(logEntry[22]) - int(logEntry[23]))
	
					#Get the content type
					if logEntry[13] == "text/html":
						content="1"
					else:
						content="0"
	
					addRecord(db, id, clientIP, destIP, timestamp, bytesDiff, content)
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
					bytesDiff=abs(int(logEntry[4]))
	
					#Get the content type
					if logEntry[9] == "text/html":
						content="1"
					else:
						content="0"
	
					addRecord(db, id, clientIP, destIP, timestamp, bytesDiff, content)
					i+=1
			
	print(str(i) + " records. ") 

def createPairs(curs):
	#Create a list of unique src and dests
	print("Creating list of Unique Source and Dest IPs.",)
	ipSets=[]
	curs.execute("SELECT DISTINCT clientip, destip FROM proxyData ORDER BY clientip")
	for row in curs:
		x=row[0]
		y=row[1]
		ipSets.append([x, y]) 
	print(str(len(ipSets)) + " records. ") 

	#Create a dictionary of destip addresses and a count of occurance 
	curs.execute("SELECT destip, COUNT(*) FROM proxyData GROUP BY destip")
	destipCount={}
	for row in curs:
		destipCount[row[0]] = row[1]
	return destipCount , ipSets

def createDeltas(curs, ipSets, destipCount):
	#Select a list of times
	print("Creating Time Deltas")
	for ipSet in ipSets:
		i=0
		timeDiffs=[]
		curs.execute("""SELECT time, bytesDiff, contentType FROM proxyData WHERE clientip=? AND destip=? ORDER BY time""", (ipSet[0], ipSet[1]))
		for row in curs:
			if i == 0:
				lastTime=row[0]
				contentSum = row[2]
				bytesSum = row[1]
			else:
				currentTime=row[0]
				diff=currentTime - lastTime
				timeDiffs.append(diff)
				lastTime=currentTime
				contentSum=contentSum + row[2]
				bytesSum=bytesSum + row[1]
			i += 1

		#Generate time information
		timeDiffs=numpy.array(timeDiffs)
		timeDiffStdDev=round(timeDiffs.std(),3)
		timeDiffMean=round(timeDiffs.mean(),2)

		#This check throws away records with a mean time of 0 
		if timeDiffMean > 0:
			beaconScore=calcBeaconScore(timeDiffStdDev, timeDiffMean, i, contentSum, ipSet[1], destipCount.get(ipSet[1]), bytesSum, logType)
			addTimeRecord(db, id, ipSet[0], ipSet[1], timeDiffMean, timeDiffStdDev, i, beaconScore)

def calcBeaconScore(stdDev, mean, count, contentSum, url, roa, bytesSum, logType): 	

	#Generate stdDev Factor
	if stdDev < 0.5:
		timeStdDevFactor=2
	elif stdDev < 1:
		timeStdDevFactor=1
	else:
		timeStdDevFactor=0

	#Generate meanFactor
	if mean > 900:
		timeMeanFactor=1
	else:
		timeMeanFactor=0

	#Generate count factor
	if count <= 3: 
		countFactor=-3
	else:
		countFactor=0

	#Generate fileType factor
	contentAvg=contentSum/ count * 100
	if contentAvg > 50:
		fileTypeFactor=1
	else:
		fileTypeFactor=0

	#Generate URL Factor
	if ipCheck(url) == True:
		ipURL=2
	else:
		ipURL=0	

	#Generate rateOfOccurance factor
	if roa >= 5:
		rateOfOccuranceFactor=0
	else:
		rateOfOccuranceFactor=1
	
	#Generate bytesFactor
	bytesAvg=bytesSum/count*100
	if logType == 'bluecoat':
		if bytesAvg > 500:
			bytesFactor=1
		else:
			bytesFactor=0
	else:
		if bytesAvg > 5000:
			bytesFactor=1
		else:
			bytesFactor=0


	#Generate a beacon Probability
	beaconScore= rateOfOccuranceFactor + fileTypeFactor + bytesFactor + timeMeanFactor + timeStdDevFactor + ipURL + countFactor
	return beaconScore

def printResults(curs): 
	print("Client IP |".rjust(18) \
                + "Dest IP |".rjust(54) \
                + "Count |".rjust(7) \
                + "Mean Time |".rjust(12) \
                + "Std Dev |".rjust(12) \
		+ "Score".rjust(7))
	print("-" * 111)

	curs.execute("SELECT clientip, destip, count, mean, stdDev, beaconScore FROM timeData ORDER BY beaconScore DESC, stdDev ASC")
	for row in curs:
		if row[5] >= 6:
			beaconProbability="High"
		elif row[5] >= 3:
			beaconProbability="Medium"
		else:
			beaconProbability="Low"

		print(row[0].rjust(16) + " |" \
			+ row[1].rjust(52) + " |" \
			+ str(row[2]).rjust(5) + " |" \
			+ str(row[3]).rjust(10) + " |" \
			+ str(row[4]).rjust(10) + " |" \
			+ beaconProbability.rjust(7) )

cmdOpts=commandLineOptions()
logType=cmdOpts[0]
logFile=cmdOpts[1]
dbInfo=dbFileCheck(dbFile)
curs=dbInfo[0]
db=dbInfo[1]

importData(db, logFile, logType)
ipPairs=createPairs(curs)
destipCount=ipPairs[0]
ipSets=ipPairs[1]
createDeltas(curs, ipSets, destipCount)
printResults(curs)
