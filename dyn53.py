#!/usr/bin/env python
# Dynamic DNS Script for AWS Route53
# Sean Greathouse 11/2015

# Most consumer grade internet connections have a public IP address that can change over time.
# In order to reliably connect from the internet to hosts and resources on a network that lack
# a dedicated static public IP, you employ 'Dynamic DNS'.
# Dynamic DNS uses a software agent on the private network that can detect changes to the
# public IP address and update a public DNS entry accordingly.
# Use cases involve hosting your own web or email server, or gaining remote access back to your home network over the internet.
# There are both commercial/freemium services and other examples of scripting against Route53.
# 
# At its core, the script determines the current public IP of the network, checks the current DNS record
# then changes the DNS record if the two addresses don't match.
#
# The script can use several methods to accomplish these tasks, so it can be adapted to different OSes and scenarios.
# Currently it has been tested on Linux, OSX, and the Tomato USB open router firmware distribution.
# The default mode uses all Python and should work on Windows.
# It should also work on the linux based DD-WRT router firmware distribution.
# 
# The default uses all python, boto3 to communicate with Route53 and dnspython for to discover the current public IP.
# Default mode requires:
# aws python sdk (aka boto3) 
# to install: pip install boto3
# dnspython
# to install: pip install dnspython
#
# see 'Advanced Options' instructions below for other modes

# To get started
# 1) Create a subdomain zone in Route53 for your dynamic dns (optional)
#    Because IAM (AWS Integrated Access Management) controls access per-zone not per record,
#    I recommend that you create a subdomain zone just for your dynamic dns.
#    If the credentials you use in this script only allow access to a subdomain zone,
#    your main DNS zone could not be compromised if the credentials from the script were exposed.
#
#    If your primary zone is foo.com, create a public zone in Route53 called bar.foo.com
#    Copy the four NS records that were created in the bar.foo.com zone.
#    They will look similar to this:
#    ns-1363.awsdns-42.org.
#    ns-1576.awsdns-05.co.uk.
#    ns-921.awsdns-51.net.
#    ns-197.awsdns-24.com.
#   
#    Create this record in the foo.com Route53 zone:
#    Name: bar.foo.com
#    Type: NS
#    Value:  <paste the four ns records from the bar.foo.com zone>
#
#    You have now delegated any records for <anyrecord>.bar.foo.com to this new zone.
#    If you want records in the main domain to take advantage of dynamic DNS you can create
#    cname reocrds from the main domain.
#    Dynamic hostname home.bar.foo.com
#    cname www.foo.com to home.bar.foo.com 

# 
# 2) Create an IAM user in AWS just for this script
#    The user does not need to have a password, just an Access Key & Secret Access Key pair.
#    Create an IAM policy to allow the user to read and write a single Route53 zone.
#    Attach the policy to your new IAM user.
#    The policy you need is in the 'IAM Policy' section at the end of this file.
#    Remember to paste the zone ID for the zone you just created into the IAM policy.
#
# 3) Configure the 'Your Variables' section below.
#
###############################################################
# Your Variables
## This top section must be configured for the script to work
aws_region = "us-east-1"  
access_key = "<yourkey>"  # AWS IAM Credential
secret_access_key = "<your secret key>"  # AWS IAM Credential
route_53_zone_id = "<your zone id>"  # the Route53 Zone you created for the script
route_53_record_name = "baz.bar.foo.com."  # The name of the record to modify
route_53_record_ttl = 60 # record TTL

###############################################################
# Advanced Options
# optionally the script can use the aws cli via a *nix shell instead of boto3 to communicate with Route53
# see route53ManagementMode in Advanced Conifg
# Requires AWS CLI http://docs.aws.amazon.com/cli/latest/userguide/installing.html
# or: pip install awscli
####
# for dns lookups you can use dig via a *nix shell
# or directly query an interface ip for routers or other devices not behind a NAT
# see 'Advanced IP Lookup' section of the config below
###############################################################
## Advanced Config
## Everything below here can be left to defaults
## Defaults settings use all python commands so can work across many platforms
## If you modify the settings below, read through the entire settings section

# The type of record, should be 'A', 
# The script allows you to use the root of a zone as your record
# So this allow us to differentiate between the root A record and other root records NS, etc.
route_53_record_type = "A"  

## The script can invoke aws cli on the shell or use the boto3 python sdk for aws_region
## pip install boto3 or pip install awscli
## use boto3 for non *nix platforms
route53ManagementMode = "boto3Mode" # options boto3Mode or awsCliMode 

## If you use awsCliMode
# The script writes a temp file to your local filesystem.
# Here you can configure the name and path of the file.
# Make sure the user running the script has write permissions to the file/path you specifiy.
route53_record_file = "./route53record.json"

## Advanced IP Lookup
##
# If your device has a local public interface, use localInterface
# Most devices will be behind a firewall & NAT, use queryOpenDns unless running on a router
# localInterface mode assumes a linux/unix environment and invokes an ifconfig command on the underlying shell
publicIpMode = "queryOpenDns" # options: localInterface or queryOpenDns

# dnsQueryMode selects whether to use the dnspython library or call the command line for dig
# digResolver mode assumes a linux/unix environment and invokes a dig command on the underlying shell
# pythonResolver mode requires dnspython, to install: pip install dnspython
dnsQueryMode = "pythonResolver" # options: pythonResolver or digResolver

# The interface ID, only needed for localInterface mode.
# use ifconfig in *nix environments to find the public interface
ethernet_interface = "eth0"
# ifconfig_regex is only needed for localInterface mode.
# The output of ifconfig varies by OS, so you may need to modify this regex.
#ifconfig_regex = r'(?<=inet\s)(\d{1,3}\.){3}\d{1,3}' # works on OSX where the format is "inet 123.456.123.456"
ifconfig_regex = r'(?<=inet\saddr:)(\d{1,3}\.){3}\d{1,3}' # works on linux where the format is "inet addr:123.456.123.456"
## END SETTINGS
###############################################################

###############################################################
# Setup & routine definitions
###############################################################
# import python modules
import json
import subprocess
import os
import re
import fileinput
###############################################################

###############################################################
# Define credentials and connections
if route53ManagementMode == "awsCliMode" or publicIpMode == "localInterface" or dnsQueryMode == "digResolver":
    myEnv = dict(os.environ)   # Make a copy of the current environment
    myEnv['AWS_ACCESS_KEY_ID'] = access_key
    myEnv['AWS_SECRET_ACCESS_KEY'] = secret_access_key
if route53ManagementMode == "boto3Mode" :
    import boto3
    route53client = boto3.client(
                    'route53', 
                    region_name=aws_region ,
                    aws_access_key_id=access_key ,
                    aws_secret_access_key=secret_access_key )
###############################################################

###############################################################
# define our exit functions
def exitError(errorText):
    print errorText
    quit()

def exitSuccess(successText):
    print successText
    quit()
###############################################################

###############################################################
# define routine to create the record json for awsCliMode
def buildJsonFile(subPublicIp):
    jsonFileBody =  "\
        {\n\
          \"Comment\": \"\",\n\
          \"Changes\": [\n\
            {\n\
              \"Action\": \"UPSERT\",\n\
              \"ResourceRecordSet\": {\n\
                \"Name\": \"%s\",\n\
                \"Type\": \"%s\",\n\
                \"TTL\": %s,\n\
                \"ResourceRecords\": [\n\
                  {\n\
                    \"Value\": \"%s\"\n\
                  }\n\
                ]\n\
              }\n\
            }\n\
          ]\n\
        }\n\
        " % (route_53_record_name, route_53_record_type, route_53_record_ttl, subPublicIp)
    jsonFile = open(route53_record_file, 'w') 
    jsonFile.write(jsonFileBody)
###############################################################


###############################################################
###############################################################
# Script Logic
###############################################################
# Find the current public IP
if publicIpMode == "localInterface":
    bashIfconfig = "ifconfig %s" % ethernet_interface
    publicIpProcess = subprocess.Popen(bashIfconfig.split(), shell=False, env=myEnv, stdout=subprocess.PIPE)
    ifConfig = publicIpProcess.communicate()[0]
    publicIpSearch = re.search(ifconfig_regex, ifConfig) 
    publicIp = publicIpSearch.group(0)
    print publicIp
elif publicIpMode == "queryOpenDns":
    if dnsQueryMode == "digResolver":
        bashDig  = "dig +short myip.opendns.com @resolver1.opendns.com"
        publicIpProcess = subprocess.Popen(bashDig.split(), shell=False, env=myEnv, stdout=subprocess.PIPE)
        publicIp = publicIpProcess.communicate()[0]
        publicIp = publicIp.rstrip()
        print publicIp
    if dnsQueryMode == "pythonResolver":
        import dns.resolver
        pyDns = dns.resolver.Resolver(configure=False)
        pyDns.nameservers = ["208.67.222.222", "208.67.220.220"]
        publicIp = (pyDns.query('myip.opendns.com')[0])
        publicIp = str(publicIp)
        print publicIp
###############################################################

###############################################################
# Find the IP associated with our current Route53 DNS record
# First declare the variable in case no record yet exists in route53.
currentRoute53Ip = "" 

if route53ManagementMode == "awsCliMode" :
    # Call the aws cli and parse the ouput
    bashRoute53Call = "aws route53 --region %s --output json list-resource-record-sets --hosted-zone-id %s" % (aws_region, route_53_zone_id)
    process = subprocess.Popen(bashRoute53Call.split(), shell=False, env=myEnv, stdout=subprocess.PIPE)
    output = process.communicate()[0]
    parsed_output = json.loads(output)
    for eachRecord in parsed_output['ResourceRecordSets']:
        if eachRecord['Name'] == route_53_record_name and eachRecord['Type'] == route_53_record_type :
            if len(eachRecord['ResourceRecords']) > 1 :
                exitError("You should only have a single value for your dynamic record.  You currently have more than one.")
            for eachSubRecord in eachRecord['ResourceRecords']:
                currentRoute53Ip = eachSubRecord['Value']
                print currentRoute53Ip

elif route53ManagementMode == "boto3Mode" :          
    currentRoute53RecordSet = route53client.list_resource_record_sets(
        HostedZoneId=route_53_zone_id ,
        StartRecordName=route_53_record_name ,
        StartRecordType=route_53_record_type ,
        MaxItems='1'
    )
    for eachRecord in currentRoute53RecordSet['ResourceRecordSets']:
        if eachRecord['Name'] == route_53_record_name :
            if len(eachRecord['ResourceRecords']) > 1 :
                exitError("You should only have a single value for your dynamic record.  You currently have more than one.")
            for eachSubRecord in eachRecord['ResourceRecords']:
                currentRoute53Ip = eachSubRecord['Value']
                print currentRoute53Ip 
###############################################################


###############################################################
# check to see if our IP has changed
if publicIp == currentRoute53Ip :
    exitSuccess("Your ip has not changed")
elif publicIp != currentRoute53Ip :
    if route53ManagementMode == "awsCliMode" :
        # first put the new IP in our json record file
        buildJsonFile(publicIp)
        route53RecordChange = "aws route53 --region %s change-resource-record-sets --hosted-zone-id %s --change-batch file://%s" % (aws_region, route_53_zone_id, route53_record_file)
        recordChangeProcess = subprocess.Popen(route53RecordChange.split(), shell=False, env=myEnv, stdout=subprocess.PIPE)
        recordChangeResult = recordChangeProcess.communicate()[0]
        exitSuccess("Your ip has been changed")
    elif route53ManagementMode == "boto3Mode" :
        changeRoute53RecordSet = route53client.change_resource_record_sets(
            HostedZoneId=route_53_zone_id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': route_53_record_name ,
                            'Type': route_53_record_type ,
                            'TTL': route_53_record_ttl ,
                            'ResourceRecords': [
                                {
                                'Value': publicIp
                                }
                            ]
                        }
                    }
                ]
            }
        )
    
    
###############################################################
###############################################################
# IAM Policy to apply to the user account that executes this script
# Remove the leading #s replace [Your Zone ID] with the actual ID, and paste into the AWS IAM console
#{
#    "Version": "2012-10-17",
#    "Statement": [
#        {
#            "Effect": "Allow",
#            "Action": [
#                "route53:ChangeResourceRecordSets"
#            ],
#            "Resource": "arn:aws:route53:::hostedzone/[Your Zone ID]"
#        },
#        {
#            "Effect": "Allow",
#            "Action": [
#                "route53:ListResourceRecordSets"
#            ],
#            "Resource": "arn:aws:route53:::hostedzone/[Your Zone ID]"
#        },
#        {
#            "Effect": "Allow",
#            "Action": [
#                "route53:GetChange"
#            ],
#            "Resource": "arn:aws:route53:::change/*"
#        }
#    ]
#}
#
