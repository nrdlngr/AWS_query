#!/usr/bin/env python
# AWS SigV4 signing tool
# 
# This script allows you to manually sign HTTP query API requests to AWS
# 
# Pass a url in quotes as an argument
#
# USAGE: 
#   queryv4.py https://s3.amazonaws.com
#   queryv4.py "GET https://ec2.amazonaws.com/?Action=DescribeRegions&Version=2013-10-15"
# 
# The script assumes that you have the AWS_ACCESS_KEY and 
# AWS_SECRET_KEY environment variables set to your AWS credentials.
# To set these up, see the following topics:
#   Windows:
#       http://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/InstallEC2CommandLineTools.html#set-aws-credentials
#   Mac or Linux:
#       http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/SettingUp_CommandLine.html#setting_up_ec2_command_linux 

import os
import sys
import urllib
import urllib2
import datetime
import string
import hmac
import hashlib
import base64
import argparse
import urlparse
import requests

def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(("AWS4" + key).encode("utf-8"), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, "aws4_request")
    return kSigning

# SAMPLE REQUESTS: If you are not passing a request via the command line, you can define one here.
# request = 'https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08'
# request = 'https://ec2.amazonaws.com/?Action=DescribeRegions&Version=2013-10-15'
# request = 'https://s3.amazonaws.com'
# request = 'http://monitoring.amazonaws.com/?Action=ListMetrics&Version=2010-08-01'

# If request is not defined yet, pull it in from the command line.
if not 'request' in locals():
   request = sys.argv[1]

# Split request into an HTTP verb and the url to sign.
http_verb = 'GET'
url = request.lstrip("GET ")

# Parse the url to get the host, path, and params.
parsed_url = urlparse.urlparse(url)

# Split the host into peices and pull the service and region from it.
# If no region is in the url, then us-east-1 is assumed.
host_parts = string.split(parsed_url.netloc, '.')
if len(host_parts) == 4:
    service = host_parts[0]
    region = host_parts[1]
else:
    service = host_parts[0]
    region = 'us-east-1'

# Pull user's AWS credentials from env vars
access_key = os.environ.get('AWS_ACCESS_KEY')
secret_key = os.environ.get('AWS_SECRET_KEY')

# Create timestamp for headers and date format for credential string
t = datetime.datetime.utcnow()
amzdate = t.strftime("%Y%m%dT%H%M%SZ")
datestamp = t.strftime("%Y%m%d")

# CREATE THE CANONICAL QUERY STRING
# Get the query parameters
query_params = urlparse.parse_qsl(parsed_url.query)
# Sort the query params by key name
sorted_query = sorted(query_params)
# Urlencode the sorted query
query_string = urllib.urlencode(sorted_query)
# Replace '+' with '%20' in query string; the previous method replaces 
# blank spaces with '+' symbols, and AWS expects '%20' instead.
canonical_query_string = query_string.replace('+', '%20')

# Create the scope and the credential string
scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
credential_string = access_key + '/' + scope
# print credential_string

signed_headers = 'host'

headers = [
    ('X-Amz-Algorithm', 'AWS4-HMAC-SHA256'),
    ('X-Amz-Date', amzdate),
    ('X-Amz-Expires', '300'),
    ('X-Amz-Credential', credential_string),
    ('X-Amz-SignedHeaders', signed_headers) 
    ]

# When sending a GET request, the headers go in the query string and they are not
# made lowercase.
canonical_headers = urllib.urlencode(sorted(headers)).replace('+', '%20')

# S3 seems to want a different payload hash than other services
if service == 's3':
    payload_hash = 'UNSIGNED-PAYLOAD'
else:
    payload_hash = hashlib.sha256("").hexdigest()

# Get the path. If path is empty, replace it with a '/' in the canonical request.
canonical_request_path = parsed_url.path
if canonical_request_path == '':
    canonical_request_path = '/'


# Create the canonical request

if canonical_query_string == '':
    canonical_request = http_verb + '\n' + canonical_request_path + '\n' + canonical_headers + '\n' + 'host:' + parsed_url.netloc + '\n' + '\n' + signed_headers + '\n' + payload_hash
else:
    canonical_request = http_verb + '\n' + canonical_request_path + '\n' + canonical_query_string + '&' + canonical_headers + '\n' + 'host:' + parsed_url.netloc + '\n' + '\n' + signed_headers + '\n' + payload_hash

# Create the string to sign
string_to_sign = 'AWS4-HMAC-SHA256' + '\n' + amzdate + '\n' + scope + '\n' + hashlib.sha256(canonical_request).hexdigest()

# Create the signing key
signing_key = getSignatureKey(secret_key, datestamp, region, service)

# Sign the string_to_sign using the signing_key
signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()
                             
# Add params and headers into one list, then urlencode them for the HTTP request
params_and_headers = query_params + headers

# Create the signed url to send in the request.
# S3 can accept requests on just the service, so we have to create a handler for requests without query parameters.
if parsed_url.path == '':
    signed_url = parsed_url.scheme + '://' + parsed_url.netloc + '?' + urllib.urlencode(params_and_headers).replace('+', '%20') + '&X-Amz-Signature=' + signature
else:
    signed_url = parsed_url.scheme + '://' + parsed_url.netloc + parsed_url.path + '?' + urllib.urlencode(params_and_headers).replace('+', '%20') + '&X-Amz-Signature=' + signature

print "\nAWS SigV4 signing tool"

# Print the request and subsequent response
print "\nBEGIN REQUEST"
print "++++++++++++++++++++++++++++++++++++"
print signed_url

r = requests.get(signed_url)

print "\nRESPONSE"
print "++++++++++++++++++++++++++++++++++++"
print r.text
