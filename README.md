# LamdaLablooter

## Overview
Organizations can have thousands of lines of code that are stored in Lambda on AWS.  This application was built to help reduce the amount of time it takes to review that code.  On our last Pen Test we had so much Lambda code to review it was impossible to parse through all of it in the short amount of time assingned to our test.  This lack of time created a necessity to automate the review of that lambda code for secrets.  Lambda Looter was born out of that automation.  Lambda Looter will take a list of profiles and scan through them and download the code you have access to and then process that code for secrets outputting any potential secrets to a loot directory.  Even though there can be a lot of false positives it makes looking for loot much faster than scanning the code itself.

lamdalooter is a Python tool for AWS Lambda code analysis.

This script will analyze all of the Lambda code that you have access to.

## configure AWS to get a list of your profiles
```
pc configure aws
cat ~/.aws/config | grep "\[profile" | cut -d " " -f 2 | cut -d "]" -f 1 >> AWSProfiles.txt
```
save the output of the above command to a text file

```
usage: LambdaLooter [-h] [--version] (-p PROFILE | -f PROFILELIST) [-r REGION] [-t THREADS] [-d]

Download your Lambda code and scan for secrets.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -p PROFILE, --profile PROFILE
                        Single AWS profile you want scan for lambda code
  -f PROFILELIST, --file PROFILELIST
                        File containing the AWS profiles you want scan for lambda code
  -r REGION, --region REGION
                        Your aws region you want to download lambda code from. Default=us-east-1.
  -t THREADS, --threads THREADS
                        Number of threads to download functions and scan for loot. Default=10.
  -d, --delete          Delete the Zip files after you are done looting. Default=False.

Download ---> Pillage ---> Loot ---> Prosper!
```
### Signatures
LambdaLooter relies on python files with signatures to determine what may be interesting
* sig_aws_key.py
    * contains signatures for all types of keys and tokens used on the web
* sig_basic_strings.py
    * contains basic strings we want to look for that may be interesting



