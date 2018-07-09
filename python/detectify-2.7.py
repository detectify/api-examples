#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hmac
import requests
from requests.auth import HTTPBasicAuth
from hashlib import sha256
from base64 import b64encode, b64decode
import sys
import time
import json
from os import walk

# Detectify public API endpoint, no trailing slash
# Python 2.7
ENDPOINT = 'https://api.detectify.com/rest/v2'

# API response codes
response_codes = {
    #200: 'Returned scan status',
    400: 'Bad request',
    401: 'Missing/invalid API key or message signature, or invalid timestamp',
    403: 'The API key cannot access this functionality',
    404: 'No scan running for the specified profile, or the specified scan profile ' +
         'does not exist or the API key cannot access the scan profile',
    500: 'An error occurred while processing the request',
    503: 'An error occurred while processing the request',
}


def make_headers(api_key, secret_key, method, path, timestamp, body=None):
    method = method.upper()
    signature = make_signature(api_key, secret_key, method, path, timestamp, body)

    return {
        'X-Detectify-Key': api_key,
        'X-Detectify-Signature': signature,
        'X-Detectify-Timestamp': str(timestamp)
    }

def make_signature(api_key, secret_key, method, path, timestamp, body=None):
    msg = method+";"+path+";"+str(api_key)+";"+str(timestamp)+";"
    if body:
        msg += body

    msg_bytes = msg.encode()
    secret = b64decode(secret_key)

    sig_bytes = hmac.new(key=secret, msg=msg_bytes, digestmod=sha256)
    sig_base64 = b64encode(sig_bytes.digest())

    return sig_base64.decode()

def check_request_error(request):
    if request.status_code in response_codes.keys():
        print "Error code " + str(request.status_code) + ": " + response_codes[request.status_code]
        return None
    return request

def request(api_key, secret_key, path, method):
    url = ENDPOINT+path
    timestamp = int(time.time())
    headers = make_headers(api_key, secret_key, method, path, timestamp)
    try:
        if method == 'GET':
            return check_request_error(requests.get(url, headers=headers))
        elif method == 'POST':
            return check_request_error(requests.post(url, headers=headers))
        elif method == 'DELETE':
            return check_request_error(requests.delete(url, headers=headers))
    except requests.exceptions.RequestException as e:
        print "[!] Error executing request"

    return

def start_scan(scan_profile, api_key, secret_key):
    path = "/scans/"+scan_profile+"/"
    req = request(api_key, secret_key, path, 'POST')
    if req != None:
        print req.text

def stop_scan(scan_profile, api_key, secret_key):
    path = "/scans/"+scan_profile+"/"
    req = request(api_key, secret_key, path, 'DELETE')
    if req != None:
        print req.text

def scan_status(scan_profile, api_key, secret_key):
    path = "/scans/"+scan_profile+"/"
    req = request(api_key, secret_key, path, 'GET')
    if req != None:
        print req.text

def get_domains(api_key, secret_key):
    path = "/domains/"
    req = request(api_key, secret_key, path, 'GET')
    if req != None:
        print json.loads(req.text)

def get_domain_profiles(api_key, secret_key, domain_token):
    path = "/profiles/"+domain_token+"/"
    req = request(api_key, secret_key, path, 'GET')
    if req != None:
        print json.loads(req.text)

def get_all_profiles(api_key, secret_key):
    path = "/profiles/"
    req = request(api_key, secret_key, path, 'GET')
    if req != None:
        return json.loads(req.text)

def profiles_scan_status(api_key, secret_key):
    profiles = get_all_profiles(api_key, secret_key)
    if profiles != None:
        for scan in profiles:
            #print i["token"]
            scan_status(scan["token"], api_key, secret_key)

def get_scan_reports(api_key, secret_key, profile):
    path = "/reports/"+profile+"/"
    req = request(api_key, secret_key, path, 'GET')
    if req != None:
        return json.loads(req.text)

def get_findings_report(api_key, secret_key, profile, report):
    path = "/fullreports/"+ profile +"/"+report+"/"
    req = request(api_key, secret_key, path, 'GET')
    if req != None:
        return json.loads(req.text)

def profiles_findings(api_key, secret_key):
    #We get all scan profiles
    profiles = get_all_profiles(api_key, secret_key)
    reports = []
    all_reports = {}

    #We get all the reports of all profiles, and
    #construct a dict with that info
    for profile in profiles:
        #reports on profile
        reports = get_scan_reports(api_key, secret_key, profile["token"])
        all_reports[profile["endpoint"]] = {"token": profile["token"], "reports": list([x["token"] for x in reports])}
    
    total = 0
    for i in all_reports.keys():
        total += len(all_reports[i]["reports"])
    
    #Gets the files already downloaded to skip them
    report_files = []
    for (dirpath, dirnames, filenames) in walk("."):
        report_files.extend(filenames)
        report_files = [files for files in report_files if ".json" in files]
        break
    
    #Deletes the reports already downloaded from the download list
    for files in report_files:
        scan, report = (files.split(".json")[0]).split("_")
        if scan in all_reports.keys():
            if report in all_reports[scan]["reports"]:
                all_reports[scan]["reports"].remove(report)
            else:
                print "Report %s not in profile %s" % (report, scan)        
        else:
            print "Profile not in list"

    to_download = 0
    for i in all_reports.keys():
        to_download += len(all_reports[i]["reports"])
    print "To download "+str(to_download)+"/"+str(total)
   
    total = to_download
    to_download = 0

    #Downloads one by one the reports and saves them to disk
    for profile in all_reports.keys():
        for report in all_reports[profile]["reports"]:
            to_download+=1
            filename = profile+"_"+report+".json"
            print "Downloading "+str(to_download)+"/"+str(total)
            file = open(filename,"w")
            file.write(json.dumps(get_findings_report(api_key, secret_key, all_reports[profile]["token"], report)))
            file.close()

    print "[DONE] All reports downloaded"
            
    
        

secretKey = 'SGVsbG8sIHdvcmxkISBJIGFtIGEgdGVhcG90IQ=='
scanProfile = ''
apiKey = ''
domainToken = ''



#ALL TESTS
#API token needs to have the privileges to do the tasks

print "[TEST] Start Scan"
start_scan(scanProfile, apiKey, secretKey)
print "[TEST] Start Scan Status"
scan_status(scanProfile, apiKey, secretKey)
print "[TEST] Stop Scan"
stop_scan(scanProfile, apiKey, secretKey)
print "[TEST] Stop Scan Status"
scan_status(scanProfile, apiKey, secretKey)
print "[TEST] Get Domains"
get_domains(apiKey, secretKey)
print "[TEST] Get Domain Profiles"
get_domain_profiles(apiKey, secretKey, domainToken)
print "[TEST] Get Profiles Scan Status"
#profile_scans_status includes the test of get_all_profiles and scan_status functions
#profiles_scan_status(apiKey, secretKey)
#Gets all the reports of all scans and saves to JSON
#profiles_findings(apiKey, secretKey)
