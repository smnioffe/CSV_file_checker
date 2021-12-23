import os
import operator
import csv
import subprocess
import io
import pandas as pd
import pyodbc
import re
import sys
import numpy as np
from dateutil.parser import parse
from datetime import datetime
from fuzzywuzzy import fuzz
from fuzzywuzzy import process







numberLinetoReadIn=1000



#Log Console Output
logFile=open("logfile.log", "a")
logFile.truncate()
logFile.close()
class Logger(object):
    def __init__(self):
        self.terminal = sys.stdout
        self.log = open("logfile.log", "a")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)  
  
sys.stdout = Logger()		
  
#Check If File Is Encrypted
def check_PGP(filePath):
	checkPGP = subprocess.Popen(['C:\GnuPG\gpg.exe','--decrypt','--list-only','--status-fd','1',filePath], 
		shell=False, 
		stdout=subprocess.PIPE, 
		stderr=subprocess.PIPE )
	encMessage=checkPGP.stdout.readlines()
	
	#print(encMessage[1])
	if len(encMessage)<>0:
		if len(encMessage)>1:
			if"NO_SECKEY" in encMessage[1]:
				encrypted="ERROR"	
			elif "GNUPG" in encMessage[0] and "NODATA" not in encMessage[0]:
				encrypted=True
			else:
				encrypted=False
		else:
			encrypted=False
	else:
		encrypted=False
	return encrypted	

	
	
#Read In Encrypted File
def read_Enc_File(filepath):
	
	memFile=''
	
	proc = subprocess.Popen(['C:\GnuPG\gpg.exe','-d',filepath], 
		shell=False, 
		stdout=subprocess.PIPE, 
		stderr=subprocess.PIPE )
	linenum = 1
	while linenum<numberLinetoReadIn+1:
	  line = proc.stdout.readline()
	  linenum += 1
	  memFile=memFile+line	
	else: proc.kill()

	return memFile


#Check Delimiters in First Line
def find_delimiter(teststr):
    possible = [',','\t','-','|']
    count = {}

    for delim in possible:
        count[delim]=teststr.count(delim)

    mostFreqDelim=max(count.iteritems(), key=operator.itemgetter(1))[0]

    return mostFreqDelim

#Get connection to write to DB
anMonCXN=pyodbc.connect('')
anMonCursor=anMonCXN.cursor()

#Get all updated SFTP Folders
SFTPcnxn = pyodbc.connect('')
SFTPcursor = SFTPcnxn.cursor()
#Check If Folder has been manually declared or if should be run from DB
try:
  folderToScan
except NameError:
	SFTPcursor.execute("exec [dbo].[get_new_unparsed_SFTPs] @outputColumn='folder'")
	
else:
	SFTPcursor.execute("select ? as folder",folderToScan)
SFTProws = SFTPcursor.fetchall()
  
for	myFolder in SFTProws:
	myFolder=str(myFolder.folder)
	
	#Get the run_id- unique id per execution.  Find the greatest one in the DB then add one
	runID=0
	anMonCursor.execute("SELECT coalesce(MAX([run_id]),0) as [run_id] FROM [{DB_NAME}].[dbo].[file_parser_output]")
	runs = anMonCursor.fetchall()
	for run in runs:
		runID=int(run.run_id)+1

	#Get Client Acronym From SFTP File Path
	clientAcr=myFolder[myFolder.find('-')+1:myFolder.find('_')]
	clientAcr=clientAcr.replace('PR-','')
	
	#Function to write output to DB and print to console
	def write_output(runID,filename,myFileAlt,type,message):
			print("%s: %s" %(type,message))
			anMonCursor.execute("INSERT INTO [{DB_NAME}].[dbo].[file_parser_output]([run_id],[source],[filename],[filename_parsed],[folder],[type],[message] ) values (?,?,?,?,?,?,?)",runID,clientAcr,filename,myFileAlt,myFolder,type,message)
			anMonCXN.commit()

			
	print("==========================================")	
	type="START"
	message=str("Validating Files in Folder: %s    Inspecting first %s rows"% (myFolder,numberLinetoReadIn))
	write_output(runID,"Run Start",numberLinetoReadIn,type,message)		
		


	
	#Check If Folder has been manually declared or if should be for every file
	try:
	  folderToScan
	except NameError:
	#Get all updated SFTP Folders
		SFTPFilecnxn = pyodbc.connect('')
		SFTPFilecursor = SFTPFilecnxn.cursor()
		SFTPFilecursor.execute("exec [dbo].[get_new_unparsed_SFTPs] @outputColumn='filename', @folderFilter=?",(myFolder))
		files = SFTPFilecursor.fetchall()
		#files=str(files.filename)
	else:	
		#Loop for All Files in Directory
		files = os.listdir(myFolder)
	
	filesCount=0
	
	for filename in files:
	
		try:
			folderToScan	  
		except NameError:
			filename=str(filename.filename)
			
		myFilePath = os.path.join(myFolder, filename)
		
		
		#Ensure File is not zipped
		if ".zip" in filename.lower():
			type="WARNING"
			message=str("ZIPPED FILE SKIPPED: %s" % (filename))
			write_output(runID,filename,"",type,message)
			print("-------------------------------------------------------------")
		elif os.path.isfile(myFilePath) and ".filepart" not in filename.lower():#ensure file exists and isn't in transit
			try:
				filesCount += 1
				
						#Parse File Name
				myFile=os.path.splitext(os.path.basename(myFilePath))[0]
				myFileOrig=myFile
				myFile=myFile.replace('_to_','')
				myFile=result = ''.join([i for i in myFile if not i.isdigit()])	
				myFile=myFile.lstrip('_').rstrip('_')
				myFile=myFile.replace('-encrypted','')
				myFile2=myFile
				myFile=re.sub('[^A-Za-z0-9]+', '', myFile)
				myFile=myFile.replace(clientAcr.replace('PR-',''),'')
				myFileAlt=myFile.lstrip('_').rstrip('s')
				#print(clientAcr,myFile2)
				
				type="MESSAGE"
				message=str("BEGIN VALDIATION: %s" % (filename))
				write_output(runID,filename,myFileAlt,type,message)
						
				#Call Function to Check if File is Encrypted
				encryptedStatus= check_PGP(myFilePath)
				
				if encryptedStatus==True:
					type="MESSAGE"
					message=str("File encrypted: %s" % (encryptedStatus))
					write_output(runID,filename,myFileAlt,type,message)
				elif encryptedStatus=="ERROR": 
					type="ERROR"
					message=str("Encryption key does not match")
					write_output(runID,filename,myFileAlt,type,message) 
				else:
					type="WARNING"
					message=str("File is not encrypted")
					write_output(runID,filename,myFileAlt,type,message)
					
				#Read First Line
				if encryptedStatus==False:
					with open(myFilePath, 'r') as f:
						first_line = f.readline()
						line_count=sum(1 for _ in f)
						#try:
						#	second_line=f.readlines()[1:]
				else:
					memFile=read_Enc_File(myFilePath)
					first_line = memFile.split('\n', 1)[0]
					line_count=len(memFile.split('\n', 1))
					#try:
					#	second_line=memFile.split('\n', 1)[2]

				if line_count<2:
					type="WARNING"
					message=str("No Data - File Skipped")
					write_output(runID,filename,myFileAlt,type,message)
				else:			
					#Identify Delimiter
					setDelimiter = find_delimiter(first_line)
						
					#Read File
					try:
						if encryptedStatus==False:
							dfFile= pd.read_csv(myFilePath, nrows=numberLinetoReadIn, sep=setDelimiter)
						else:
							dfFile= pd.read_csv(io.BytesIO(memFile), dtype=object, nrows=numberLinetoReadIn, sep=setDelimiter)	
					except:
						#If there is an error reading the file, try command again but with "error_bad_lines" set to false, and log the error
						
						if encryptedStatus==False:
							dfFile= pd.read_csv(myFilePath, nrows=numberLinetoReadIn, sep=setDelimiter, error_bad_lines=False)
						else:
							dfFile= pd.read_csv(io.BytesIO(memFile), dtype=object, nrows=numberLinetoReadIn, sep=setDelimiter, error_bad_lines=False)
						
						type="ERROR"
						message=str("Rows Skipped")
						write_output(runID,filename,myFileAlt,type,message)
							

						
					#Check for Empty Columns
					nullHeader=dfFile.columns.str.contains('Unnamed:').sum()
					
					#Check if File Contains Junk Data in First Few Lines.
					if nullHeader>0:
						type="ERROR"
						message=str("%s NULLs in first row"%(nullHeader))
						write_output(runID,filename,myFileAlt,type,message)
						
						nullsInRows=dfFile.isnull().sum(axis=1)
						nullsInRows=nullsInRows[nullsInRows>3]
						nullsInRows=list(nullsInRows.index)
						nullsInRows=max(nullsInRows)
						if nullsInRows<dfFile.shape[1]:
							if encryptedStatus==False:
								dfFile= pd.read_csv(myFilePath, nrows=numberLinetoReadIn, sep=setDelimiter,skiprows=nullsInRows+2)
							else:
								dfFile= pd.read_csv(io.BytesIO(memFile), dtype=object, nrows=numberLinetoReadIn,skiprows=nullsInRows+2)
							type="ERROR"
							message=str("First %s rows of file do no contain parsable data"%(nullsInRows+2))
							write_output(runID,filename,myFileAlt,type,message)

					#DEV Time Format
					# def is_date(string):
						# string=string.lstrip(' ').rstrip(' ')
						# if len(string)<9:
							# return False
						# else:
							# try:					
								# dt=parse(string, fuzzy=False, default=datetime(5, 6, 29)).date()							
								# if dt.year==5:
									# return False
								# elif dt.month==6 and (dt.year <1700 or dt.year >2100):
									# return False
								# else:
									# return True
							# except ValueError:
								# return False						
							
					
					# df_date=dfFile[:1]
					# df_date2=df_date.apply(lambda x: is_date(str(x[0])))
					
					
					# df_date2=df_date2.loc[df_date2.isin([True])]
					# date_columns=df_date2.index.values.tolist() 
					# df_date=df_date[date_columns]
					# print(df_date)
					
							
				
					
					emptySpace=0
					for col in dfFile.columns:
						if ' ' in col:
							emptySpace += 1
					if emptySpace>0:
						type="WARNING"
						message=str("space found in %s column headers"%(emptySpace))
						write_output(runID,filename,myFileAlt,type,message)
					#Number of Rows
					#dfRemoveNull=dfFile.replace(r'\s+',np.nan,regex=True).replace('',np.nan)
					#print(dfRemoveNull.shape)	
						
					
					
					#Get Predefined File Layout from {DB_NAME} DB	
					definedHeadersList= None
					InfDBcnxn = pyodbc.connect('DRIVER={SQL Server};SERVER={SRV_NAME};DATABASE={DB_NAME}_DEV;Trusted_Connection=TRUE')
					cursor = InfDBcnxn.cursor()
					cursor.execute("SELECT distinct [ColumnList],[Delimiter],[TextQualifier] FROM [{DB_NAME}_DEV].[dbo].[Presource_Tables] T  JOIN [{DB_NAME}_DEV].[dbo].[PreSource] S on  s.[Presource_ID]=t.[Presource_ID]  and (s.[PreSource_Acronym]=? or s.[PreSource_Acronym]='PR-'+?) and (replace(t.table_name,'_','')=? or replace(t.table_name,'_','')=?)", (clientAcr,clientAcr,myFile,myFileAlt))
					rows = cursor.fetchall()
					#Try Second Match Pattern
					if rows==[]:
						cursor.execute("SELECT distinct [ColumnList],[Delimiter],[TextQualifier] FROM [{DB_NAME}_DEV].[dbo].[Presource_Tables] T  JOIN [{DB_NAME}_DEV].[dbo].[PreSource] S on  s.[Presource_ID]=t.[Presource_ID]  and (s.[PreSource_Acronym]=? or s.[PreSource_Acronym]='PR-'+?) and ? like '%'+t.table_name+'%'", (clientAcr,clientAcr,myFileOrig))
						rows = cursor.fetchall()
					#Try Third Match Pattern	
					if rows==[]:
						cursor.execute("SELECT distinct [ColumnList],[Delimiter],[TextQualifier] FROM [{DB_NAME}_DEV].[dbo].[Presource_Tables] T  JOIN [{DB_NAME}_DEV].[dbo].[PreSource] S on  s.[Presource_ID]=t.[Presource_ID]  and (s.[PreSource_Acronym]=? or s.[PreSource_Acronym]='PR-'+?) where (CHARINDEX(replace(file_pattern,'#',''),'_'+?)>0 or CHARINDEX(replace(file_pattern,'#',''),?)>0) or ? like '%'+file_pattern+'%'", (clientAcr,clientAcr,myFile2,myFile2,myFileOrig))								
						rows = cursor.fetchall()
					#Try File Template Pattern
					if rows==[]:
						cursor.execute("SELECT distinct [Source_Acronym]  ,[Sft_Name], [FlatFile_Template_Name],[Table_Name],[File_Pattern] ,[TextQualifier],[Delimiter] ,[ColumnList]  FROM [{DB_NAME}_DEV].[dbo].[Source] s  join  [{DB_NAME}_DEV].[dbo].[Clients] c  on s.Client_ID=c.Client_ID  join [{DB_NAME}_DEV].[lookup].[Connector_Type] t  on s.Connector_Type_ID=t.Connector_Type_ID join [{DB_NAME}_DEV].[lookup].[Source_Software] ss  on ss.Sft_ID=s.Sft_ID join [{DB_NAME}_Dev].[dbo].[v_pre-processing_Templates]  p on [FlatFile_Template_Name]=sft_name where ([Source_Acronym]= ? or [Source_Acronym]='PR-'+?)and ? like '%'+[File_Pattern]+'%'",(clientAcr,clientAcr,myFile2))
						rows = cursor.fetchall()
					#Try File Standard QDW Definition
					if rows==[]:
						cursor.execute("SELECT distinct [ColumnList],[Delimiter],[TextQualifier] FROM [{DB_NAME}].[dbo].[standard_mappings] where ? like '%'+table_name+'%'", (myFile))
						rows = cursor.fetchall()
						if rows!=[]:
							type="MESSAGE"
							message=str("Validating against QDW standard definition. No pre-processing definitions found for source acrnonym:%s and table name:%s" % (clientAcr,myFileAlt))
							write_output(runID,filename,myFileAlt,type,message)
						
					for row in rows:
						definedHeadersList=row.ColumnList
						definedDelimiter=row.Delimiter or ','
						definedQualifier=row.TextQualifier
						
					#Error if No pre-processing Match is Found
					if definedHeadersList==None:
						type="ERROR"
						message=str("no match found for source acrnonym:%s and table name:%s Ensure pre-processing definitions exist in the ETL DB" % (clientAcr,myFileAlt))
						write_output(runID,filename,myFileAlt,type,message)
						
					else:		
						definedHeaders=definedHeadersList.split(',')
						definedHeaders=map(lambda x:x.lower(),definedHeaders)
						
						#Set Issue Count to 0
						issue=0
						
						#If File is Quote Qualified, Check for Presence of Qualifiers in the first line
						if definedQualifier=='"' and first_line.count(definedQualifier)<>len(dfFile.columns)*2:
							issue=1
							if first_line.count(definedQualifier)==0:
								type="WARNING"
								message=str("headers are not quote qualified")
								#write_output(runID,filename,myFileAlt,type,message)
							else:
								type="WARNING"
								message=str("possible delimiter inconsistency")
								write_output(runID,filename,myFileAlt,type,message)

						#Rename Tab Delimiter for Constiteny for Both Sources and Human Read Printability
						if definedDelimiter== '\\t':
							definedDelimiter='TAB'
							
						if setDelimiter== '\t':
							setDelimiter='TAB'
						
						#Check Delimiter Constiteny
						if definedDelimiter<>setDelimiter:
							type="ERROR"
							message=str("delimter mismatch. Expeted %s but file contains %s" % (definedDelimiter,setDelimiter))
							write_output(runID,filename,myFileAlt,type,message)
							
						#Check Header Mismatch
						dfFile.columns = map(str.lower, dfFile.columns)
						headerDiffs=list(list((set(dfFile.columns)-set(definedHeaders)))+list((set(definedHeaders)-set(dfFile.columns))))
						#sorted(headerDiffs, key=lambda x: definedHeaders.index(x))#dfFile.columns.get_loc(x))
						
						#Get Columns W/O Special characters
						dfFileParsed=[re.sub('[^A-Za-z0-9]+', '',x.upper()) for x in dfFile.columns] 
						definedHeadersParsed=[re.sub('[^A-Za-z0-9]+', '',x.upper()) for x in definedHeaders] 
						
						
						if dfFile.shape[1]!=len(definedHeaders):#headerDiffs!=[]:
							type="ERROR"							
							message=str("file columns: %s     defined columns: %s" %(dfFile.shape[1],len(definedHeaders)))
							write_output(runID,filename,myFileAlt,type,message)
						successColCount=0
							
						
						
						
						#Begin Column Level Validation
						#If File and Definition Columns Match Check Individual Column Orders
						if len(dfFile.columns)==len(definedHeaders) and headerDiffs==[]:
							for i,col in enumerate(definedHeaders):
								if dfFile.columns[i].upper()==col.upper():
									successColCount=successColCount+1
								else:
									defineColumnParsed=re.sub('[^A-Za-z0-9]+', '', dfFile.columns[i].upper())
									fileColumnParsed=re.sub('[^A-Za-z0-9]+', '', col.upper())
									if defineColumnParsed==fileColumnParsed:
										type="WARNING"
										message=str("special character mismatch in position[%s] file contains '%s' instead of defined column '%s'" %(i+1,dfFile.columns[i].upper(),col.upper()))
										write_output(runID,filename,myFileAlt,type,message)
									else:
										if fuzz.ratio(dfFile.columns[i].upper(),col.upper())>.89:
											type="WARNING"
											message=str("slight difference in column name file contains '%s' in position[%s] for defined column '%s' " % (dfFile.columns[i].upper(),i+1,col.upper()))
											write_output(runID,filename,myFileAlt,type,message)		
										else:
											type="ERROR"
											message=str("file contains '%s' in position[%s] for defined column '%s' " % (dfFile.columns[i].upper(),i+1,col.upper()))
											write_output(runID,filename,myFileAlt,type,message)										
								if successColCount==len(definedHeaders) and len(dfFile.columns)==len(definedHeaders) and i==len(definedHeaders)-1:# and issue==0:
									type="SUCCESS"
									message=str("All Columns Match")
									write_output(runID,filename,myFileAlt,type,message)

									
						#If File and Definition # Columns DO NOT Match Check All Columns Against Definition					
						else:
							parsedMatches = []
							mismatches = []
							for dif in headerDiffs:
								
								difParsed=re.sub('[^A-Za-z0-9]+', '',dif.upper())#Get dif with special characters stripped
								if difParsed not in parsedMatches:
									if difParsed in dfFileParsed and difParsed in definedHeadersParsed:
										parsedMatches.append(difParsed)
										if definedHeadersParsed.index(difParsed)==dfFileParsed.index(difParsed):
											position=definedHeadersParsed.index(difParsed)
											type="WARNING"
											message=str("special character mismatch in position[%s] file contains '%s' instead of defined column '%s'" % (position+1,dfFile.columns[position].upper(),definedHeaders[position].upper()))
											write_output(runID,filename,myFileAlt,type,message)
										else:
											filePosition=dfFileParsed.index(difParsed)
											headerPosition=definedHeadersParsed.index(difParsed)
											type="ERROR"
											message=str("misalignment and special character mismatch; file contains '%s' in position[%s] instead of defined column '%s' in position[%s] " % (dfFile.columns[filePosition].upper(),filePosition+1,definedHeaders[headerPosition].upper(),headerPosition+1))
											write_output(runID,filename,myFileAlt,type,message)
											mismatches.append(definedHeaders[headerPosition].upper())
									else:
										#If the extra column is found in the definition only
										if dif in definedHeaders and dif.upper() not in mismatches and 'Unnamed:' not in dif:	
											if definedHeaders.index(dif)<dfFile.shape[1]:
												position=definedHeaders.index(dif) #Position of extra field in definition
												#if fuzz.ratio(dif.upper(),dfFile.columns[position].upper())>.89:
													#print ("WARNING: slight difference in column name for defined column %s file has %s column in position[%s]" % (dif.upper(),dfFile.columns[position].upper(),position+1))
												#else:
												type="ERROR"
												message=str("file is misaligned and missing defined column '%s' and instead has '%s' column in position[%s]" % (dif.upper(),dfFile.columns[position].upper(),position+1))
												write_output(runID,filename,myFileAlt,type,message)									
												mismatches.append(dfFile.columns[position].upper())
											else:
												type="ERROR"
												message=str("defined column '%s' in position[%s] missing from file" % (dif.upper(),definedHeaders.index(dif)+1))
												write_output(runID,filename,myFileAlt,type,message)
										
										#If the extra column is found in the extract only
										if dif in dfFile.columns and dif.upper() not in mismatches:
											if dfFile.columns.get_loc(dif)<len(definedHeaders):
												position=dfFile.columns.get_loc(dif) #Position of extra field in extract
												#if fuzz.ratio(dif.upper(),definedHeaders[position].upper())>.89:
													#print ("WARNING: slight difference in column name and contains undefined column %s instead of defined column %s in position[%s]" % (dif.upper(),definedHeaders[position].upper(),position+1))
												#else:
												type="ERROR"
												message=str("file is misaligned and contains undefined column '%s' instead of defined column '%s' in position[%s]" % (dif.upper(),definedHeaders[position].upper(),position+1))
												mismatches.append(definedHeaders[position].upper())
												write_output(runID,filename,myFileAlt,type,message)
											else:
												type="ERROR"
												message=str("undefined column present in file '%s' in position [%s]" % (dif.upper(),dfFile.columns.get_loc(dif)+1))
												write_output(runID,filename,myFileAlt,type,message)
						
						#PK Verifciation. Guess PK using file name
						filePK=myFileAlt.replace("plan_","").lower()+"_id"
						if filePK in dfFile.columns:
							if dfFile[filePK].isnull().sum()==dfFile.shape[0]:
								type="ERROR"
								message=str("'%s' primary key does not contain any values" %(filePK.upper()))
								write_output(runID,filename,myFileAlt,type,message)
							elif dfFile[filePK].isnull().sum()>0:
								type="ERROR"
								message=str("'%s' primary key contains blank values" %(filePK.upper()))
								write_output(runID,filename,myFileAlt,type,message)
							elif len(dfFile[filePK].unique())+1<dfFile.shape[0]:
								type="ERROR"
								message=str("'%s' primary key contains duplicate values; %s duplicate values out of %s inspected columns" %(filePK.upper(),dfFile.shape[0]-len(dfFile[filePK].unique())+1,dfFile.shape[0]))
								#print(len(dfFile[filePK].unique())+1,dfFile.shape[0])
								write_output(runID,filename,myFileAlt,type,message)
						
						#Get Empty Columns
						dfFile.replace(r'\s+', np.nan, regex=True)					
						emptryColumns=dfFile.isnull().sum()
						emptryColumns=emptryColumns[emptryColumns==dfFile.shape[0]]
						emptryColumns=list(emptryColumns.index)
						if len(emptryColumns)>0 and encryptedStatus!="ERROR":
							for empCol in emptryColumns:
								if filePK != empCol.lower():
									type="WARNING"
									message=str("'%s' does not contain any values" %(empCol.upper()))
									write_output(runID,filename,myFileAlt,type,message)
									
									
						#Check for carriage returns	or line breaks					
						for col in dfFile.select_dtypes([np.object]).columns[1:]:
							if dfFile[col].str.contains('\r|\n').any()==True:
								type="ERROR"
								message=str("'%s' contains carriage returns or line breaks" %(col))
								write_output(runID,filename,myFileAlt,type,message)
			except:
				type="ERROR"
				message=str("ERROR PARSING FILE: %s" % (filename))
				write_output(runID,filename,"",type,message)
				
			print("-------------------------------------------------------------")
		


	if filesCount==0:
		type="END"
		message=str("No Files Found in Directory")
		write_output(runID,"Run End","",type,message)	
	else:
		type="END"
		if filesCount==1:
			message=str("Validation Complete %s File Parsed" %(filesCount))
		else:
			message=str("Validation Complete %s Files Parsed" %(filesCount))
		write_output(runID,"Run End",filesCount,type,message)
		
# SFTPcnxnFinal = pyodbc.connect('')
# SFTPcursorFinal = SFTPcnxnFinal.cursor()
# SFTPcursorFinal.execute("EXEC [dbo].[file_monitor_email]")
# SFTPcursorFinal.commit()