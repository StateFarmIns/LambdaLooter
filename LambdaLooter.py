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

from signatures.constants.constants import FILE_TYPES

PROG_NAME = "LamdaLooter"
PROG_VER = 0.1
PROG_DESC = "Download your Lambda code and scan for secrets."
PROG_EPILOG = "Download ---> Pillage ---> Loot ---> Prosper!"

def parse_args():
	"""
	Parse cmd line args
	"""
	parser = argparse.ArgumentParser(prog=PROG_NAME, description=PROG_DESC, epilog=PROG_EPILOG)
	parser.add_argument("--version", action="version", version="%(prog)s v"+str(PROG_VER))
	
	# either -p or -f but not both cause that is wack bro
	profilegroup = parser.add_mutually_exclusive_group(required=True)
	profilegroup.add_argument("-p", "--profile", dest="profile", help="Single AWS profile you want scan for lambda code")
	profilegroup.add_argument("-f", "--file", dest="profileList", help="File containing the AWS profiles you want scan for lambda code")
	
	parser.add_argument("-r", "--region", dest="region", default="us-east-1", help="Your aws region you want to download lambda code from. Default=us-east-1.")
	parser.add_argument("-t", "--threads", dest="threads", default=10, type=int, help="Number of threads to download functions and scan for loot. Default=10.")
	parser.add_argument("-fv", "--versions", dest="versions", action='store_true', help="Download all versions of the Lambda code. Default=False.")
	parser.add_argument("-d", "--delete", dest="deldownloads", action='store_true', help="Delete the Zip files after you are done looting. Default=False.")
    
	args = parser.parse_args()
    
	'''
	if ((args.profile is None) and (args.profileList is None)):
		parser.error("You must specify either -p or -f")
		raise SystemExit(-1)
	
	if ((args.profile is not None and args.profileList is not None)):
		parser.error("You can only select -p or -f, not both")
		raise SystemExit(-1)

	if ((args.profile is None) or (args.profileList is None)):
		strFileCheck = os.path.isfile(args.profileList)
		if not strFileCheck:
			print("Your profile list file does not exist!")
			raise SystemExit(-1)
	'''
	return args




def main(region, threads, deldownloads, getversions, profileList=None, profile=None):       
	"""
	Main function
	Sets the stage for everything!
	Variables - 
	region: aws region
	threads: number of threads for downloads
	profileList: Defaults to None, file with list of AWS profiles
	profile: Defaults to None, single AWS profile
	"""

	strLoot = os.path.isdir('./loot')
	if not strLoot:
		os.mkdir('loot')
		print("Created the folder:", 'loot')
			
	else:
		print('loot', "folder already exists.")
	
	if profileList is not None:
		# if user supplies file, we need to do some checking before going to awsProfileSetup
		startProfileList(profileList, region, threads, deldownloads, getversions)
	
	if profile is not None:
		# user supplied single aws profile, lets roll
		awsProfileSetup(profile, region, threads, deldownloads, getversions)

def startProfileList(profileList, region, threads, deldownloads, getversions):
	"""
	Start working through the file of AWS profiles
	Variables - 
	region: aws region
	threads: number of threads for downloads
	profileList: file with list of AWS profiles
	"""
	strFileCheck = os.path.isfile(profileList)
	if not strFileCheck:
		print("Your profile list file does not exist!")
		raise SystemExit(-1)
	with open(profileList, "r") as pf:
		for myline in pf: 
			myline = myline.rstrip('\n')
			if myline != "": 
				awsProfileSetup(myline, region, threads, deldownloads, getversions)

def awsProfileSetup(profile, region, threads, deldownloads, getversions):
	"""
	AWS functions to interact with single AWS profiles.
	Either from a file list or single specified profile
	Variables - 
	region: aws region
	threads: number of threads for downloads
	profile: the AWS profile to interact with
	"""
	print("")
	os.environ["AWS_PROFILE"] = profile
	#cmd = f'echo $AWS_PROFILE'
	#os.system(cmd)
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
	threads: number of threads for searcher
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
											
											if mrPat in a:
												for m in re.finditer(mrPat, a):
													start = m.start()
													line_no = a[:start].count(b"\n") + 1
													start_of_line = a[:start].rfind(b"\n") + 1
													end_of_line = a[start:].find(b"\n")
													fullLine = a[start_of_line:end_of_line+start]
													
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
	Filter out known false postives, based on signatures
	Variables - 
	output: the output detected by a signature
	filters: the list of filters supplied by a given signature
	Returns:
	True if filter matches in output
	False if no match occurs
	"""
	for filter in filters:
		if filter.encode() in output:
			return True
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
	Thread download lambda 'downloadFunctions' function
	Variables - 
	region: aws region
	threads: number of threads for downloads
	profile: the AWS profile lambdas are downloaded from
	"""
	cmd="aws lambda list-functions --region " + region + " | jq \'.Functions[].FunctionName\' | tr -d '\"'"
	process = subprocess.Popen(cmd,shell=True,stdin=None,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	# The output from your shell command
	
	result=process.stdout.readlines()
	
	if len(result) >= 1:
		with ThreadPoolExecutor(threads) as executor:
			
			futures = [executor.submit(downloadFunctions, profile, line, region, getversions) for line in result]
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

def downloadEnvCommand(cmd, **kwargs):

	process = subprocess.Popen(cmd,shell=True,stdin=None,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	result=process.stdout.readlines()
	
	if len(result) >= 1:
		if not kwargs["strLootFile"]:
			with open(kwargs["filepath"], 'w') as lf:
				pass
			with open(kwargs["filepath"], 'a') as outputfile:
				outputfile.write("----------------------------\n")
				outputfile.write("ENVVAR: {}\n".format(result))
				outputfile.write("----------------------------\n")
				outputfile.write("\n")

def downloadLambdaCommand(cmd, **kwargs):
	
	call(cmd,shell=True,stdin=None)
	
	strLoot = os.path.isdir('./loot/env')
	if not strLoot:
		os.mkdir('./loot/env')
		#print("Created the folder:", './loot/env')

	filepath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "loot/env/" + kwargs["profile"] + "-" + kwargs["strFunction"] + "-environmentVariables-loot.txt")
	strLootFile = os.path.isfile(filepath)
	return filepath, strLootFile			
		
		
def downloadFunctions(profile, line, region, getversions):
	"""
	downloadFunctions download lambdas function
	Variables - 
	region: aws region
	line: lambda download name
	profile: the AWS profile lambdas are downloaded from
	"""
	strFunction = line.decode("utf-8")
	strFunction = strFunction.strip()
	print("Downloading code for: " + strFunction)
	if getversions:
		
		cmd = "aws lambda list-versions-by-function --function " + strFunction + " --region " + region + " --profile " + profile +" | jq \'.Versions[].Version\' | tr -d '\"'"
		process = subprocess.Popen(cmd,shell=True,stdin=None,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		result=process.stdout.readlines()
		if len(result) >= 1:
			for line in result:
				line = line.decode("utf-8")
				line = line.rstrip('\n')
				if ("$LATEST") in line:
					line = "LATEST"
					print("Downloading code for: " + strFunction + " Version: " + line)
					v_cmd = "aws lambda get-function --region " + region + " --profile " + profile + " --function-name " + strFunction + " --query 'Code.Location' | xargs wget -O ./loot/" + profile + "/" + strFunction + "-version-" + line + ".zip 2> /dev/null"
					fname = strFunction + "-version-" + line 
					print("Checking Environment Variables for " + strFunction + " Version: " + line)	
					e_cmd = "aws lambda get-function --region " + region + " --function-name " + strFunction + " --profile " + profile + " --query 'Configuration.Environment.Variables'"

				else:
					print("Downloading code for: " + strFunction + " Version: " + line)
					v_cmd = "aws lambda get-function --region " + region + " --profile " + profile + " --function-name " + strFunction + " --qualifier " + line + " --query 'Code.Location' | xargs wget -O ./loot/" + profile + "/" + strFunction + "-version-" + line + ".zip 2> /dev/null"
					fname = strFunction + "-version-" + line 
					print("Checking Environment Variables for " + strFunction + " Version: " + line)
					e_cmd = "aws lambda get-function --region " + region + " --function-name " + strFunction + " --profile " + profile + " --qualifier " + line + " --query 'Configuration.Environment.Variables'"
				
				f,s = downloadLambdaCommand(v_cmd, profile=profile, strFunction=fname)
				downloadEnvCommand(e_cmd, filepath=f, strLootFile=s)
	else:
			
			print("Downloading code for: " + strFunction)
			cmd = "aws lambda get-function --region " + region + " --function-name " + strFunction + " --query  'Code.Location' | xargs wget -O ./loot/" + profile + "/" + strFunction + ".zip 2> /dev/null"
			f,s = downloadLambdaCommand(cmd, profile=profile, strFunction=strFunction)
			
			print("Checking Environment Variables for " + strFunction)
			cmd = "aws lambda get-function --region " + region + " --function-name " + strFunction + " --query 'Configuration.Environment.Variables'"
			downloadEnvCommand(cmd, filepath=f, strLootFile=s)

			


if __name__ == "__main__":
	args = parse_args()
	
	main(args.region, args.threads, args.deldownloads, args.versions, profileList=args.profileList, profile=args.profile)

