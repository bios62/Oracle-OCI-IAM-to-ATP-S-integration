import io
import json
import base64
import oci
import logging
import hashlib
import requests 
import urllib3
import random
from random import shuffle
import string

#
# Constants (well not rellay...)
#
CREATEUSERACTION=1
DROPUSERACTION=2
ASSIGNROLEACTION=3
REVOKEROLEACTION=4
PASSWORDLENGHT=14

DEBUG_ERROR=1
DEBUG_WARN=2
DEBUG_INFO=3
DEBUG_FULL=4

FUNCTIONTYPE=0
CMDLINETYPE=1

# Map global variables based on execution mode
if __name__ != '__main__':
	from fdk import response
	logType=3
	defaultDebugLevel=DEBUG_FULL
	debugLevel=defaultDebugLevel
	ociConfig={}
	invocationType=FUNCTIONTYPE
else:
	import argparse
	import os
	import platform

	#
	# Create dummy response Class 
	class dummyResponse:
		def __init__(self):
			self.responsData=None
		def __str__(self):
			try:
				hString=json.dumps(self.responseData)
			except:
				hString=str(responseData)
			return(f"{self.responseData}({hString})")
		def Response(self,ctx=None,response_data=None,headers=None):
			self.responseData=response_data
			self.headers=headers
			return(self.__str__())
	#
	# Dummy Context class
	class dummyContext:
		def __init__(self):
			self.config=None
		def __str__(self):
			return(str(config))
		def setConfig(self,newConfig):
			self.config=newConfig
		def Config(self):
			return(self.config)
	
	# paramters for invoking diretly with python cmd line
	logType=4
	defaultDebugLevel=3
	debugLevel=defaultDebugLevel
	invocationType=CMDLINETYPE
	if platform.system().lower() == 'linux':
		siteConfigFile="/home/ios/fnproject/config.json"
	else:
		siteConfigFile="g:\\demo_projects\\fnproject\\config.json"
	response=dummyResponse()
	ctx=dummyContext()
	
#
# Common Globals
#
signer=None
logBuffer=[]

"""
Helper funtions 

"""
#
# Print debug messages if debug level is below
# debugLogLevel
def addDebugLog(logMessage,requestedDbgLevel):
	global debugLevel
	#logging.getLogger().info("Request level: "+str(requestedDbgLevel)+" debugLevel: "+str(debugLevel))
	#logging.getLogger().info("----->"+logMessage+"<------")
	if requestedDbgLevel <= debugLevel:
		#logging.getLogger().info("Log should be generated")
		#logging.getLogger().info("-->"+logMessage+"<--")
		appendLog(logMessage)
	else:
		#logging.getLogger().info("Log should be generated but fails")
		#logging.getLogger().info("-->"+logMessage+"<--")
		appendLog(' Log level above limit: '+logMessage)
# Setter function for log Type
def setLogType(newLogType):
	global logType
	logType=newLogType

# Setter function for debugloglevel
def setDebugLevel(newDebugLevel):
	global debugLevel
	debugLevel=newDebugLevel
#
#  Write log messages
#  logType 0, dont write any messages
#  logType 1, write to str buffer only
#  logType 2, write to funtion default logger only
#  logType 4, write to stdout
#
# addDebugLog
def appendLog(logMessage):
	global logBuffer
	global logType
	if logType == 0:
		return
	if (logType & 1) >0 : 
		#logging.getLogger().info("Log type 1")
		logBuffer.append(logMessage)
	if (logType & 2) >0 :
		#logging.getLogger().info("Log type 2")
		logging.getLogger().info(logMessage)
	if (logType & 4) >0 :
		#logging.getLogger().info("Log type 4")
		print(logMessage)
#
# Convert buffer to JSON array and add key
#
def toJsonArray(keyName,textBuffer):
	buffer={}
	jbuf={}
	for i in range(0,len(textBuffer)):
		buffer[i]=textBuffer[i]
	jbuf[keyName]=textBuffer
	return(json.dumps(jbuf))
#
# getConfig
#
#  Fetches configuration variables#
#  Return False if any variable is missing
#  Experiemntal, fetch all config
#
def getConfig(cfg):
	configVars={}
	mandatoryKeys=['secret_type','rolemapper','clientid_ocid','clientsecret_ocid','dbURI']
	for key in mandatoryKeys:
		if key in cfg:
			configVars[key]=cfg[key]
		else:
			addDebugLog("Mandatory Config Variable: "+key+" is missing",DEBUG_INFO)
			return(False)
	optionalKeys=['bucket_name','file_name']
	for key in optionalKeys:
		if key in cfg:
			configVars[key]=cfg[key]
		else:
			addDebugLog("Optional Config Variable: "+key+" is missing",DEBUG_INFO)
	return(configVars)

# prettyStrPOST
def prettyStrPOST(req):
		"""
		At this point it is completely built and ready
		to be fired; it is "prepared".

		However pay attention at the formatting used in
		this function because it is programmed to be pretty
		printed and may differ from the actual request.
		"""
		return('{}\n{}\r\n{}\r\n\r\n{}'.format(
				'-----------START-----------',
				req.method + ' ' + req.url,
				'\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
		req.body,
		))
"""
OCi Autonomous Database ORDS REST funtions

"""
# generateDBPassword
# Geneartes a complex autonomous database password
# Minimum 2 of each tupe: Upperace, Lower case, digit and special character (#$_)
def generateDBPassword():
		# Minimum password requirement, one lowercase, one uppercase, one digit, 12 characters length
		# Generate two lowercase
		partialPassword = ''.join(random.choice(string.ascii_lowercase) for i in range(2))
		# Generate two uppercase
		partialPassword = partialPassword+''.join(random.choice(string.ascii_uppercase) for i in range(2))
		# Generate two digits
		partialPassword = partialPassword+''.join(random.choice(string.digits) for i in range(2))
		# Generate two special characters
		partialPassword = partialPassword+''.join(random.choice('#$_#$_#$_') for i in range(2))
		# Generate the remaining part
		partialPassword = partialPassword+''.join(random.choice(string.ascii_letters + string.digits + "#_$") for i in range(PASSWORDLENGHT-6))
		# As the password format now is static, shuffle it
		partialList = list(partialPassword)
		shuffle(partialList)
		newPassword = ''.join(partialList)
		return(newPassword)
#
# createDbToken
# Simple OAUTH client credentials flow
#
# Uri is in format  http://<server name| autonomous name>/ords/<schema name>
#
def getDBtoken(dbURI,clientID,clientSecret):
	# Set the API endpoint URL
	endPoint="/oauth/token"
	url = dbURI+endPoint
	auth64=base64.b64encode((clientID+':'+clientSecret).encode('utf-8')).decode()
	# Feth the DB token
	headers = {
		"Content-Type": "application/x-www-form-urlencoded",
		"Authorization":"Basic "+auth64
	}
	payload = "grant_type=client_credentials"
	try:
		rsp=requests.post(url,headers=headers,data=payload)
	except Exception as httpError:
		addDebugLog('DB token http exception',DEBUG_ERROR)
		addDebugLog(httpError,DEBUG_ERROR)
		if debugLevel == DEBUG_FULL:
			dbgreq=requests.Request('POST',url,headers=headers,data=payload)
			prepared=dbgreq.prepare()
			postReqestDump=prettyStrPOST(prepared)
			addDebugLog(postReqestDump,DEBUG_FULL)
		return(False)
	if(rsp.status_code >201):
		addDebugLog('DB token http error',DEBUG_ERROR)
		addDebugLog(rsp.status_code,DEBUG_ERROR)
		if debugLevel == DEBUG_FULL:
			dbgreq=requests.Request('POST',url,headers=headers,data=payload)
			prepared=dbgreq.prepare()
			postReqestDump=prettyStrPOST(prepared)
			addDebugLog(postReqestDump,DEBUG_FULL)
		return(False)
	return(json.loads(rsp.text))

def execDBSQL(url,token,headers,payload):

	try:
		addDebugLog('Processing SQL statement',DEBUG_ERROR)
		addDebugLog('With headers: '+json.dumps(headers),DEBUG_ERROR)
		addDebugLog('With payload: '+payload,DEBUG_ERROR)
		rsp=requests.post(url,headers=headers,data=payload)
	except Exception as httpError:
		addDebugLog('DB SQL execution http exception',DEBUG_ERROR)
		addDebugLog(httpError,DEBUG_ERROR)
		if debugLevel == DEBUG_FULL:
			dbgreq=requests.Request('POST',url,headers=headers,data=payload)
			prepared=dbgreq.prepare()
			postReqestDump=prettyStrPOST(prepared)
			addDebugLog(postReqestDump,DEBUG_FULL)
		return(False)
	if(rsp.status_code >201):
		addDebugLog('DB SQL execution http  error',DEBUG_ERROR)
		addDebugLog(rsp.status_code,DEBUG_ERROR)
		addDebugLog(rsp.text,DEBUG_ERROR)
		if debugLevel == DEBUG_FULL:
			dbgreq=requests.Request('POST',url,headers=headers,data=payload)
			prepared=dbgreq.prepare()
			postReqestDump=prettyStrPOST(prepared)
			addDebugLog(postReqestDump,DEBUG_FULL)
		return(False)
	sqlResponse=json.loads(rsp.text)
	if 'errorCode' in sqlResponse['items'][0] and str(sqlResponse['items'][0]['errorCode']) != 0 :
		addDebugLog('DB SQL execution SQL error',DEBUG_ERROR)
		addDebugLog("SQL error code: "+str(sqlResponse['items'][0]['errorCode']),DEBUG_ERROR)
		addDebugLog("SQL error text: "+sqlResponse['items'][0]['errorDetails'],DEBUG_ERROR)
		return(False)
	return(json.loads(rsp.text))

# CreateDBUser
#
# Uri is in format  http://<server name| autonomous name>/ords/<schema name>
#
# Reference documentation for ORDS sql processing
# https://blog.cloudnueva.com/apex-ords-and-rest-enabled-sql
def modifyDBUser(actionType,dbURI,dbToken,userName=None,password=None, roleName=None):

	endPoint='/_/sql'
	# Set the API endpoint URL
	url= dbURI+endPoint
	sqlStatement={}
	
	# common properties for all actions

	# Set the request headers
	headers = {
		"Content-Type": "application/json",
		"Authorization": "Bearer "+dbToken
	}

	if actionType == CREATEUSERACTION:

		# Set the request body
		#sqlStatement['statementText']="select '"+userName+"'||'"+password+"','create' from dual;"

		# Random generate password if password is not set
		if password is None:

		# Minimum password requirement, one lowercase, one uppercase, one digit, 12 characters length
		# Generate two lowercase
		# Perhaps add some code for mailing the password
		#
			newPassword=generateDBPassword()
		else:
			newPassword=password
		sqlStatement['statementText']="create user "+userName+' identified by "'+newPassword+'";'
		payload = json.dumps(sqlStatement)
		sqlResponse=execDBSQL(url,dbToken,headers,payload)
		if not sqlResponse:
			addDebugLog("User Creation failed",DEBUG_ERROR)
			return(False)
		else:
			defaultRoles='connect,resource'
			sqlStatement['statementText']="grant connect,resource to "+userName+";"
			payload = json.dumps(sqlStatement)
			sqlResponse=execDBSQL(url,dbToken,headers,payload)
			if not sqlResponse:
				addDebugLog("User default role grant failed",DEBUG_ERROR)
				return(False)
		addDebugLog('User: '+userName+' successfully added',DEBUG_INFO)
	elif actionType == DROPUSERACTION:

		# Set the request body
		sqlStatement['statementText']="drop user "+userName+" cascade;"
		payload = json.dumps(sqlStatement)
		sqlResponse=execDBSQL(url,dbToken,headers,payload)
		if not sqlResponse:
			addDebugLog("Drop user failed",DEBUG_ERROR)
			return(False)
		addDebugLog('User: '+userName+' successfully dropped',DEBUG_INFO)
	elif actionType == ASSIGNROLEACTION:

		# Set the request body
		sqlStatement['statementText']="grant "+roleName+" to "+userName+";"
		payload = json.dumps(sqlStatement)
		sqlResponse=execDBSQL(url,dbToken,headers,payload)
		if not sqlResponse:
			addDebugLog("User: "+userName+" failed to be assigned to role: "+roleName,DEBUG_ERROR)
			return(False)
		addDebugLog("User: "+userName+" successfully added to role: "+roleName,DEBUG_INFO)
	elif actionType == REVOKEROLEACTION:

		# Set the request body
		sqlStatement['statementText']="revoke "+roleName+" from "+userName+";"
		payload = json.dumps(sqlStatement)
		sqlResponse=execDBSQL(url,dbToken,headers,payload)
		if not sqlResponse:
			addDebugLog("User: "+userName+" failed to revoked from role: "+roleName,DEBUG_ERROR)
			return(False)
		addDebugLog("User: "+userName+" successfully revoked from role: "+roleName,DEBUG_INFO)
	else:
		addDebugLog("Unrecognized action: "+actionType,DEBUG_ERROR)
		return(False)
	return(True)
"""

Native OCI SDK based funtions

"""
#
# Fecth text value of secret from OCI Vault
#
# Recuire: OCID of Secret
#
# Return False on error
#
def get_text_secret(secret_ocid):
	global signer
	global ociConfig
	#
	# Allocate ociSecret client and fetch secret
	#
	try:
		client = oci.secrets.SecretsClient(config=ociConfig, signer=signer)
		secret_content = client.get_secret_bundle(secret_ocid).data.secret_bundle_content.content.encode('utf-8')
		#
		# Decode Secret
		#
		decoded_secret_content = base64.b64decode(secret_content).decode("utf-8")
		addDebugLog("Secret content base64:  "+decoded_secret_content,DEBUG_FULL)
	except Exception as ex:
		addDebugLog("ERROR: failed to retrieve the secret content"+str(ex),DEBUG_FULL)
		return(False)
	return (decoded_secret_content)

#
# Store a text block to objectstorage
#
# Return true on successfull storage
#
def saveToBucket(bucketName,fileName,textBuffer):
	global signer
	global ociConfig
	#
	# Allocate OCi Signer and oci_objectstorage Client
	#
	object_storage_client = oci.object_storage.ObjectStorageClient(config=ociConfig, signer=signer)
	addDebugLog("Saving to bucket:  "+bucketName+" "+fileName,DEBUG_FULL)
	try:
		nameSpace = object_storage_client.get_namespace().data
	except Exception as e:
		addDebugLog("Failed to fetch namespace",DEBUG_ERROR)
		print(str(e))
		return(False)
	addDebugLog("Namespace fetched: "+nameSpace,DEBUG_FULL)
	try:
		object_storage_client.put_object(
			namespace_name=nameSpace, 
			bucket_name=bucketName, 
			object_name=fileName, 
			put_object_body=textBuffer)
	except Exception as e:
		addDebugLog("Error when saving to: "+bucketName+"/"+fileName,DEBUG_ERROR)
		addDebugLog(str(e),DEBUG_ERROR)
		return(False)
	addDebugLog("Successfully saved to: "+bucketName+"/"+fileName,DEBUG_FULL)
	return(True)


#
#  Default handler when called as funtion
#
#
def handler2(ctx, data: io.BytesIO = None):
	global invocationType
	try:
		return(handler(ctx,data))
	except (Exception, ValueError) as ex:
		if (ex is None):
			print("Execution failed (None)")
			return response.Response(
			ctx, response_data=json.dumps(
				{"message": "Execution error (None): "}),
				headers={"Content-Type": "application/json"}
		)
		else:
			addDebugLog("Execution failed: "+str(ex), DEBUG_INFO)
			print("Execution failed: "+str(ex))
			return response.Response(
			ctx, response_data=json.dumps(
				{"message": "Execution error: "+str(ex)}),
				headers={"Content-Type": "application/json"}
			)
	return response.Response(
		ctx, response_data=json.dumps(
			{"message": "Success "}),
			headers={"Content-Type": "application/json"}
		)
#
# Return True if processing went well, return error message othervise
def processEvent(cfg,eventBody):
	global ociConfig

	# 
	#  Fetch common parameters
	eventType=eventBody["eventType"]

	# Check for roleMapper in the evnt of assign/Revoke roles
	# roleMapper is non mandatory parameter, but mandatory for assign/revoke
	# However users can be assigned roles, without being provisioned to Autonomous.
	# In this example, if the group does not exists in the rolemapper it simply means that
	# the group assignment should not be provisioned or deprovisioned

	#
	# Fetch username
	dbUserName=getIdentityName(ociConfig,signer,eventBody,'userId')
	if dbUserName == False:
		addDebugLog("username: "+dbUserName+" could not be fetched from  OCI IAM",DEBUG_ERROR)
		return("username: "+dbUserName+" could not be fetched from  OCI IAM")

	if eventType == 'com.oraclecloud.identitycontrolplane.addusertogroup' or eventType == 'com.oraclecloud.identitycontrolplane.removeuserfromgroup':
		# Verify if rolemapper is defined
		#
		if 'rolemapper' in cfg:
			logging.getLogger().info("Role mapper: "+cfg['rolemapper'])
			try:
				roleMapper=json.loads(cfg['rolemapper'])
			except (Exception, ValueError) as ex:
				addDebugLog("Malformed rolemapper: "+cfg['rolemapper'],DEBUG_ERROR)
				return("Malformed rolemapper")
		else:
			addDebugLog("Mandatory parameter Role mapper is not defined",DEBUG_ERROR)
			return("Mandatory parameter Role mapper is not defined ")
		
		#
		# Get the group/rolename 
		groupName=getIdentityName(ociConfig,signer,eventBody,'groupId')
		if groupName == False:
			addDebugLog("groupname could not be fetched from OCI IAM",DEBUG_ERROR)
			return("groupname could not be fetched OCI IAM")

		# Retrieve the db role to be granted/revoked
		if groupName in roleMapper:
			dbMappedRole=roleMapper[groupName]
			addDebugLog("Mapping to dbrole: "+dbMappedRole,DEBUG_INFO)
		else:
			addDebugLog("No db role mapping exists for group: "+dbMappedRole,DEBUG_INFO)
			return(True) # Which is fine, it basically means that teh group is not going to be provisioned/deprovisioned to the db

	#
	# Prepare and fetch db token
	#
	# Fetch and decrypt clientID for db
	#
	clientid=get_text_secret(cfg['clientid_ocid'])
	if clientid == False:
		addDebugLog("clientid retrieval failed",DEBUG_ERROR)
		return("clientid retrieval failed")
	#
	# Fetch and decrypt ClientSecret for db
	#
	clientsecret=get_text_secret(cfg['clientsecret_ocid'])
	if clientsecret == False:
		addDebugLog("client secret retrieval failed",DEBUG_ERROR)
		return("client secret retrieval failed")

	# Get db token
	dbURI=cfg['dbURI']
	dbToken=getDBtoken(dbURI,clientid,clientsecret)['access_token']

	if dbToken == False:
		addDebugLog("db token creation failed ",DEBUG_ERROR)
		return("db token creation failed ")

	# Process event types individually
	if eventType == 'com.oraclecloud.identitycontrolplane.addusertogroup':

		# Grant mapped role to db user
		if modifyDBUser(ASSIGNROLEACTION,dbURI,dbToken, userName=dbUserName,roleName=dbMappedRole) == False:
			addDebugLog("User: "+dbUserName+" to group assignment failed "+dbMappedRole,DEBUG_ERROR)
			return("User: "+dbUserName+" to group assignment failed "+dbMappedRole)
		else:
			addDebugLog("User: "+dbUserName+" successfully assigned to group "+dbMappedRole,DEBUG_FULL)
	elif eventType == 'com.oraclecloud.identitycontrolplane.removeuserfromgroup':

		# Revoke access from dbrole
		if modifyDBUser(REVOKEROLEACTION,dbURI,dbToken, userName=dbUserName,roleName=dbMappedRole) == False:
			addDebugLog("User: "+dbUserName+" to group revoke failed "+dbMappedRole,DEBUG_ERROR)
			return("Use: "+dbUserName+"r to group revoke failed "+dbMappedRole)
		else:
			addDebugLog("User: "+dbUserName+" successfully revoked from group "+dbMappedRole,DEBUG_FULL)
	elif eventType == 'com.oraclecloud.identitycontrolplane.createuser':

		# create user in autonomous
		if modifyDBUser(CREATEUSERACTION,dbURI,dbToken,userName=dbUserName, roleName=None) == False:
			addDebugLog("User creation failed "+dbUserName,DEBUG_ERROR)
			return("User creation failed "+dbUserName)
		else:
			addDebugLog("User "+dbUserName +" successfully created ",DEBUG_FULL)
	elif eventType == 'com.oraclecloud.identitycontrolplane.deleteuser':

		# drop user from autonomous
		if modifyDBUser(DROPUSERACTION,dbURI,dbToken,userName=dbUserName, roleName=None) == False:
			addDebugLog("Drop user  failed "+dbUserName,DEBUG_ERROR)
			return("Drop user failed "+dbUserName)
		else:
			addDebugLog("User "+dbUserName +" successfully deleted ",DEBUG_INFO)
	else:
		addDebugLog('undefined eventtype: '+eventtype,DEBUG_ERROR)
		return('undefined eventtype: '+eventtype)
	#
	# Everything is good
	return(True)

def getIdentityName(ociConfig,signer,eventBody,identityType):

	# Get the userID and groupID OCI from the eventBody

	if identityType in eventBody['data']["additionalDetails"]:
		identityFactory=oci.identity.IdentityClient(ociConfig,signer=signer)
		identityId=eventBody['data']["additionalDetails"][identityType]
		try:		
			if(identityType == 'userId'):
				identityName=(identityFactory.get_user(identityId)).data.name
			elif (identityType == 'groupId'):
				identityName=(identityFactory.get_group(identityId)).data.name
		except (Exception) as ex:
			addDebugLog("Execution of identity client SDK failed for "+identityType+" with OCID: "+identityId,DEBUG_ERROR)
			addDebugLog(str(ex), DEBUG_ERROR)
			return(False)
	else:
		addDebugLog('Wrong event body type, "+identityType+" is not in event body', DEBUG_ERROR)
		return(False)
	print(identityId)
	return(identityName)



def handler(ctx, data: io.BytesIO = None):
	global signer
	global invocationType
	#
	# Note start of function
	#
	addDebugLog("iamsync V2 function start",DEBUG_INFO)
	#
	# Allocate signer object when inviked as funtion
	# Set in __main__ if invoked as cmdline
	#
	if invocationType == FUNCTIONTYPE:
		signer = oci.auth.signers.get_resource_principals_signer()
	else:
		# Allocate dummy response object
		global Response
		response = dummyResponse()
	#
	#  Parse the JSON payload
	#
	#
	try:
		eventBody = json.loads(data.getvalue())
		addDebugLog(json.dumps(eventBody),DEBUG_INFO)
		saveToBucket('customlog','event.txt',json.dumps(eventBody))
	except (Exception, ValueError) as ex:
		addDebugLog('error parsing json data payload: ' + str(ex),DEBUG_ERROR)
		addDebugLog(str(data.getvalue()),DEBUG_ERROR)
		return response.Response(
		ctx, response_data=json.dumps(
			{"message": "Message Body data missing or parse failed"}),
			headers={"Content-Type": "application/json"}
		)
	if 'name' in eventBody:
		name = eventBody.get("name")

	#
	# Get secret OCID from configuration
	#

	cfg=getConfig(dict(ctx.Config()))
	if cfg == False:
		#
		# Return and stop processing
		#
		addDebugLog("Fetch of config data failed",DEBUG_ERROR)
		return response.Response(
		ctx, response_data=json.dumps(
			{"message": "Fetch of config data failed"}),
		headers={"Content-Type": "application/json"}
		)

	#
	#  Get event if triggered by a event
	#
	result=processEvent(cfg,eventBody)
	if result == True:
		addDebugLog("Event processed successfully",DEBUG_INFO)
	else:
		addDebugLog("Handler: "+result,DEBUG_INFO)

	# Save log to OCI Bucket
	#
	if 'bucket_name' in cfg and 'file_name' in cfg:
		saveToBucket(cfg['bucket_name'],cfg['file_name'],'\n'.join(logBuffer))
	#
	# Return result
	#
	if result == True:
		return response.Response(
		ctx, response_data=json.dumps({"status":"Autonomous sync completed"}),
		headers={"Content-Type": "application/json"}
		)
	else:
		return response.Response(
			ctx, response_data=toJsonArray('logdata',logBuffer),
			headers={"Content-Type": "application/json"}
		)

"""|
Test funtions
"""


#
# Main for rapid testing
#

def main():
	global signer
	global defaultLogLevel
	global ociConfig
	global debugLevel
	global logType
	#
	logType=4   # Print to screen and allocate buffer
	debugLevel=4  # log everything for debug test purpose
	#
	#  Look up configuration file
	#
	argsParser=argparse.ArgumentParser(description='iamsync test')
	argsParser.add_argument("--logtype",default=logType,type=str,help="Log Type [1|2|4|5|7]")
	argsParser.add_argument("--debuglevel",default=debugLevel,type=str,help="debug Level >0 <1000")
	argsParser.add_argument("--configfile",default=siteConfigFile,type=str,help="Config File")
	argsParser.add_argument("--signer",default="file",type=str,help="[file|ip] (ip=instance principal")
	argsParser.add_argument("--eventfile",default='event.json',type=str,help="filename of simulated event")

	args=argsParser.parse_args()
	setDebugLevel(int(args.debuglevel))
	setLogType(int(args.logtype))
	addDebugLog("Commandline version 1.0",DEBUG_INFO)

	#
	# Read and parse configuration file
	#
	with open(args.configfile) as f:
		configText = f.read()
	try:
		cfg=json.loads(configText)
	except (Exception, ValueError) as ex:
		print('error parsing json configuration: ' + str(ex),DEBUG_ERROR)
		return(1)
	with open(args.configfile) as f:
		configText = f.read()
	#
	# Read json file with event
	
	with open(args.eventfile) as f:
		eventText = f.read()
	try:
		eventBody=json.loads(eventText)
	except (Exception, ValueError) as ex:
		print('error parsing json event: ' + str(ex),DEBUG_ERROR)
	data=io.BytesIO()
	data.write(bytes(eventText,'utf-8'))
	#
	# Load configuration
	#
	config=getConfig(cfg)
	if(config == False ):
		addDebugLog("Config parameters missing",DEBUG_ERROR)
		return(1)
	if not ('profile-name' in cfg):
		addDebugLog("OCI Profile Missing",DEBUG_ERROR)
		return(1)
	addDebugLog("Config loaded OK",DEBUG_INFO)
	if	args.signer == 'file':
		ociConfig = oci.config.from_file(profile_name=cfg['profile-name'])
		signer=oci.signer.Signer(ociConfig['tenancy'],ociConfig['user'],ociConfig['fingerprint'],ociConfig['key_file'])
	elif args.signer == 'ip':
		signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
	else:
		print("signer argument is illegal, legal values: file|ip")
		return(1)
	addDebugLog("Signed Successfull",DEBUG_INFO)
	
	#
	# Test of function
	#

	ctx=dummyContext()
	ctx.setConfig(config)
	#cfg=getConfig(dict(ctx.Config()))
	handler(ctx,data)

if __name__ == '__main__':
	main()
