#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hmac
import requests
from requests.auth import HTTPBasicAuth
from hashlib import sha256
from base64 import b64encode, b64decode
import sys
import time

# Detectify public API endpoint, no trailing slash
# Python 2.7
ENDPOINT = 'https://api.detectify.com/rest'

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
    path = "/v2/scans/"+scan_profile+"/"
    req = request(api_key, secret_key, path, 'POST')
    if req != None:
        print req.text

def stop_scan(scan_profile, api_key, secret_key):
    path = "/v2/scans/"+scan_profile+"/"
    req = request(api_key, secret_key, path, 'DELETE')
    if req != None:
        print req.text

def scan_status(scan_profile, api_key, secret_key):
    path = "/v2/scans/"+scan_profile+"/"
    req = request(api_key, secret_key, path, 'GET')
    if req != None:
        print req.text

def get_domains(api_key, secret_key):
    path = "/v2/domains/"
    req = request(api_key, secret_key, path, 'GET')
    if req != None:
        print eval(req.text)

def get_domain_profiles(api_key, secret_key, domain_token):
    path = "/v2/profiles/"+domain_token+"/"
    req = request(api_key, secret_key, path, 'GET')
    if req != None:
        print eval(req.text)

def get_all_profiles(api_key, secret_key):
    path = "/v2/profiles/"
    req = request(api_key, secret_key, path, 'GET')
    if req != None:
        return eval(req.text)

def profiles_scan_status(api_key, secret_key):
    profiles = get_all_profiles(api_key, secret_key);
    if profiles != None:
        for scan in profiles:
            #print i["token"]
            scan_status(scan["token"], api_key, "")


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
profiles_scan_status(apiKey, secretKey)
