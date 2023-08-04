import os
import json
import argparse
import subprocess
import zipfile
import pathlib
from zipfile import ZipFile
import re
import glob
import importlib
import importlib.util
from subprocess import call
from concurrent.futures import ThreadPoolExecutor, wait
import shutil
import gc
import pathlib
import boto3
from boto3 import Session
import requests

from signatures.constants.constants import FILE_TYPES, G_FILTERS

PROG_NAME = "LamdaLooter"
PROG_VER = 0.4
PROG_DESC = "Download your Lambda code and scan for secrets.  Default is to use Credential file for authentication"
PROG_EPILOG = "Download ---> Pillage ---> Loot ---> Prosper!"

def parse_args():
	"""
	Parse cmd line args
	"""
	parser = argparse.ArgumentParser(prog=PROG_NAME, description=PROG_DESC, epilog=PROG_EPILOG)
	parser.add_argument("--version", action="version", version="%(prog)s v"+str(PROG_VER))
	
	# either -p or -f but not both cause that is wack bro
	#profilegroup = parser.add_mutually_exclusive_group(required=True)
	#profilegroup.add_argument("-p", "--profile", dest="profile", help="Single AWS profile you want scan for lambda code")
	#profilegroup.add_argument("-f", "--file", dest="profileList", help="File containing the AWS profiles you want scan for lambda code")
	parser.add_argument("-p", "--profile", dest="profile", help="Single AWS profile you want scan for lambda code. Defaults to credentials file.")
	parser.add_argument("-r", "--region", dest="region", default="us-east-1", help="Your aws region you want to download lambda code from. Default=us-east-1.")
	parser.add_argument("-t", "--threads", dest="threads", default=10, type=int, help="Number of threads to download functions and scan for loot. Default=10.")
	parser.add_argument("-fv", "--versions", dest="versions", action='store_true', help="Download all versions of the Lambda code. Default=False.")
	parser.add_argument("-d", "--delete", dest="deldownloads", action='store_true', help="Delete the Zip files after you are done looting. Default=False.")
    
	args = parser.parse_args()
    
	return args


def main(region, threads, deldownloads, getversions, profile=None):       
	"""
	Main function
	Sets the stage for everything!
	Variables - 
	region: aws region
	threads: number of threads for downloads
	deldownloads: YES or NO
	getversions: YES or NO
	profile: the AWS profile lambdas are downloaded from 
	"""
	

	strLoot = os.path.isdir('./loot')
	if not strLoot:
		os.mkdir('loot')
		print("Created the folder:", 'loot')
			
	else:
		print('loot', "folder already exists.")
	
	if profile is None:
		# if user doesn't supply a profile, we need grab the credential file and loop through the profiles.
			
			#setting this up for future Profile multi-threading
			with ThreadPoolExecutor(threads) as executor:
				
				futures = [executor.submit(awsProfileSetup, profileCurrent, region, threads, deldownloads, getversions) for profileCurrent in boto3.session.Session().available_profiles]
				#wait for all tasks to complete
				wait(futures)
			
	if profile is not None:
		# user supplied single aws profile, lets roll

			awsProfileSetup(profile, region, threads, deldownloads, getversions)

def awsProfileSetup(profile, region, threads, deldownloads, getversions):
	"""
	AWS functions to interact with AWS profiles.
	Either from a file list or single specified profile
	Variables - 
	profile: the AWS profile to interact with
	region: aws region
	threads: number of threads for downloads
	deldownloads: YES or NO
	getversions: YES or NO
	"""
	
	
	print (profile)
	boto3.setup_default_session(profile_name=profile)
	sts_client = boto3.client('sts')

	os.environ["AWS_PROFILE"] = profile

	print("Creating directory to store functions")
	
	strExists = os.path.isdir('./loot/' + profile)
	if not strExists:
		os.mkdir('./loot/' + profile)
		print("Created the folder:", profile)
	
	else:
		print(profile, "folder already exists....moving on.")
	
	downloadLambdas(profile, region, threads, getversions, deldownloads)
	threadSecrets(threads, deldownloads, profile)

def threadSecrets(threads, deldownloads, profile):
	"""
	Thread the checkSecrets function
	Variables - 
	threads: number of threads for downloads
	deldownloads: YES or NO
	profile: the AWS profile to interact with
	"""
	print("Scanning for Secrets")
	rootdir = './loot'
	files = glob.glob(rootdir + r'/' + profile + '/*.zip', recursive=True)
	
	with ThreadPoolExecutor(threads) as executor:
			
		futures = [executor.submit(checkSecrets, f, deldownloads, profile) for f in files]
		#wait for all tasks to complete
		wait(futures)

	if deldownloads:
		deleteDownload(profile)

def checkSecrets(f,deldownloads, profile):
	"""
	Search through lambda zip for secrets based on signatures
	Variables - 
	f: zip file to search through
	"""
	#keep for debugging oldschool way!
	#print(files) # as list
	#print(f) # nice looking single line per file
	try:
		with ZipFile(f, "r") as inzip:
			for name in inzip.namelist():
				if pathlib.Path(name).suffix in FILE_TYPES:
					with inzip.open(name) as zipfile:
						a = zipfile.read()
						sigfiles = os.listdir(os.path.join(os.path.dirname(os.path.realpath(__file__)), "signatures"))
						for sigfile in sigfiles:
							try:
								if sigfile.startswith('sig_'):
									#pull in all sig files from the signature dir
									#prepare the module name so we can dynamically import it
									#dynamically import the sig file so we can use the Sig dict inside
									sigfilePath =  os.path.join(os.path.dirname(os.path.realpath(__file__)), "signatures/" + sigfile)
									jsonSigs = json.load(open(sigfilePath))
									for sigType in jsonSigs[0]["sigs"]:
										if sigType['type'] == 'regex':
											for outp in re.finditer(b"%b" % sigType['pattern'].encode(), a, re.MULTILINE | re.IGNORECASE):
												start = outp.span()[0]
												line_no = a[:start].count(b"\n") + 1
												try:
													output = str(outp.group(), 'UTF-8')
												except:
													output = "Way too ugly...moving on"
												prettyPrintThatOutput(profile, {
													'title': jsonSigs[0]["title"], 
													'zip': f, 
													'lamda': name,
													'description': sigType['caption'],
													'output': output,
													'line_no': line_no
													})

										elif sigType['type'] == 'match':
											mrPat = sigType['pattern'].encode()
											print(mrPat)
											
											if mrPat in a:
												for m in re.finditer(mrPat, a):
													start = m.start()
													line_no = a[:start].count(b"\n") + 1
													start_of_line = a[:start].rfind(b"\n") + 1
													end_of_line = a[start:].find(b"\n")
													fullLine = a[start_of_line:end_of_line+start]
													
													if filterFPs(fullLine, sigType["filters"]):
														continue
													
													prettyPrintThatOutput(profile, {
														'title': jsonSigs[0]["title"],  
														'zip': f, 
														'lamda': name,
														'description': 'Found pattern match: {}'. format(sigType['pattern']),
														'output': fullLine,
														'line_no': line_no
														})
													
										else:
											continue
							except Exception as e:
								print("Something happened and the world is probably going to end {}".format(e.strerror))
							
						del a
						gc.collect()	

					

	except Exception as e:
		print("That zip file was wack! {}".format(e.strerror))

	if deldownloads:
		os.remove(f)

def filterFPs(output, filters: list) -> bool:
	"""
	Filter out known false postives, based on signatures and global filters
	Variables - 
	output: the output detected by a signature
	filters: the list of filters supplied by a given signature
	Returns:
	True if filter matches in output
	False if no match occurs
	"""
	try:

		# Check global filters
		for g_filter in G_FILTERS:
			if g_filter.encode() in output:
				return True
	
		#Check match specific filters
		for filter in filters:
			if filter.encode() in output:
				return True
		
		return False
	
	except Exception as e:
		print("Error with sig fp filter, you did bad things: {}".format(e))
		return False

def deleteDownload(profile):
	"""
	Delete the downloaded zip
	Variables - 
	profile: name of profile to match to directory name for deleting
	"""
	try:
	
		filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/{}".format(profile))
		shutil.rmtree(filepath, ignore_errors=True)
	
	except Exception as e:
		print("Error: {0} : {1}".format(filepath, e.strerror))

def prettyPrintThatOutput(profile, output: dict):
	"""
	Pretty print found secretes to console and file
	Variables -
	profile: the AWS profile lambdas are downloaded from 
	output: Found secrets from given signature
	"""
	filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/" + profile + "-{}-loot.txt".format(os.path.basename(output['zip'])))
	
	print("-*-*- This sig matched {0}. Check file for loot {1}-{2}-loot.txt.".format(output['title'], profile, os.path.basename(output['zip'])))
	strLootFile = os.path.isfile(filepath)
	if not strLootFile:
		with open(filepath, 'w') as lf:
			pass

	with open(filepath, 'a') as outputfile:
		outputfile.write("----------------------------\n")
		outputfile.write("Found something GOOOOOD!\n")
		outputfile.write("Sig File: {}\n".format(output['title']))
		outputfile.write("ZIP file: {}\n".format(output['zip']))
		outputfile.write("Lambda File: {}\n".format(output['lamda']))
		outputfile.write("Description: {}\n".format(output['description']))
		outputfile.write("Line No: {}\n".format(output['line_no']))
		outputfile.write("Goodies: {}\n".format(output['output']))
		outputfile.write("----------------------------\n")
		outputfile.write("\n")

def downloadLambdas(profile, region, threads, getversions, deldownloads):
	"""
	Thread download lambda 'checkVersions' function
	Variables - 
	profile: the AWS profile lambdas are downloaded from
	region: aws region
	threads: number of threads for downloads
	getversions: YES or NO
	deldownloads: Should we delete data after we are done?
	"""

	lambda_client = boto3.client('lambda',region_name=region)

	func_paginator = lambda_client.get_paginator('list_functions')
	for func_page in func_paginator.paginate():
	
		with ThreadPoolExecutor(threads) as executor:
				
			futures = [executor.submit(checkVersions, profile, func['FunctionArn'], region, getversions) for func in func_page['Functions']]
			#wait for all tasks to complete
			wait(futures)

	
	zipEnvironmentVariableFiles(profile, deldownloads)

def zipEnvironmentVariableFiles(profile, deldownloads):

	zipDirectory = pathlib.Path("./loot/env")
	zipDirectory.mkdir(exist_ok=True)
	filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/" + profile + "/" + "envVariables.zip")
	print("Writing ZIP file to scan for loot!")
	with zipfile.ZipFile(filepath , mode="w") as archive:
		for file_path in zipDirectory.iterdir():
			archive.write(file_path, arcname=file_path.name)
			if deldownloads:
				os.remove(file_path)
	
def downloadExecution(profile, strFunction, region):
	"""
	execute the download of the lambdas function(s) and Envionrment Varilables
	Variables - 
	profile: the AWS Profile we are looting
	region: aws region
	strFunction: arn of the lambda to download
	profile: the AWS profile lambdas are downloaded from
	"""

	lambda_client = boto3.client('lambda',region_name=region)

	func_details = lambda_client.get_function(FunctionName=strFunction)
	downloadDir = "./loot/" + profile + "/" + func_details['Configuration']['FunctionName']  + "-version-" + func_details['Configuration']['Version'] + ".zip" 
	print("Downloading code for: " + profile + ":" + func_details['Configuration']['FunctionName'] + " Version: " + func_details['Configuration']['Version'])

	url = func_details['Code']['Location']
	
	r = requests.get(url)
	with open(downloadDir, "wb") as code:
		code.write(r.content)

	print("Checking Environment Variables for " +profile +":" + func_details['Configuration']['FunctionName']  + " Version: " + func_details['Configuration']['Version'])

	strLoot = os.path.isdir('./loot/env')
	if not strLoot:
		os.mkdir('./loot/env')

	saveEnvFilePath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/env/" + profile + "-" + func_details['Configuration']['FunctionName'] + "-"  + func_details['Configuration']['Version'] + "-environmentVariables-loot.txt")

	env_details = lambda_client.get_function_configuration(FunctionName=strFunction)	
	details = env_details['Environment']['Variables']

	with open(saveEnvFilePath, 'a') as outputfile:
		outputfile.write("----------------------------\n")
		outputfile.write("ENVVAR: {}\n".format(details))
		outputfile.write("----------------------------\n")
		outputfile.write("\n")

def checkVersions(profile, strFunction, region, getversions):
	"""
	check if we are downloading all versions of the lambdas function calls downloadExecution
	If we are downloading multiple versions paginate
	Variables - 
	profile: the AWS Profile we are looting
	strFunction: arn of the lambda to download
	region: aws region
	getversions: YES or NO

	"""

	lambda_client = boto3.client('lambda',region_name=region)

	if getversions:
		
		func_paginator = lambda_client.get_paginator('list_versions_by_function')
		
		for func_page in func_paginator.paginate(FunctionName=strFunction):
			for func in func_page['Versions']:
				strFunction = func['FunctionArn']
				downloadExecution(profile, strFunction, region)
	else:
		downloadExecution(profile, strFunction, region)


if __name__ == "__main__":
	args = parse_args()
	
	main(args.region, args.threads, args.deldownloads, args.versions, profile=args.profile)

