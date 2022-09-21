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
import pandas as pd
import datetime as dt
import csv


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


def make_headers(apiKey, secret_key, method, path, timestamp, body=None):
	method = method.upper()
	signature = make_signature(apiKey, secret_key, method, path, timestamp, body)

	return {
		'X-Detectify-Key': apiKey,
		'X-Detectify-Signature': signature,
		'X-Detectify-Timestamp': str(timestamp)
	}

def make_signature(apiKey, secret_key, method, path, timestamp, body=None):
	msg = method+";"+path+";"+str(apiKey)+";"+str(timestamp)+";"
	if body:
		msg += body
	msg_bytes = msg.encode()
	secret = b64decode(secret_key)

	sig_bytes = hmac.new(key=secret, msg=msg_bytes, digestmod=sha256)
	sig_base64 = b64encode(sig_bytes.digest())

	return sig_base64.decode()

def check_request_error(request, ):
	if request.status_code in response_codes.keys():
		print("Error code " + str(request.status_code) + ": " + response_codes[request.status_code])
		print('')
		return None
	return request

def request(apiKey, secret_key, path, method, payload={}):
	url = ENDPOINT+path
	timestamp = int(time.time())
	headers = make_headers(apiKey, secret_key, method, path, timestamp)
	try:
		if method == 'GET':
			return check_request_error(requests.get(url, headers=headers))
		elif method == 'POST':
			print(json.dumps(payload))
			return check_request_error(requests.post(url, data=json.dumps(payload), headers=headers))
		elif method == 'PUT':
			print(json.dumps(payload))
			return check_request_error(requests.put(url, data=json.dumps(payload), headers=headers))
		elif method == 'DELETE':
			return check_request_error(requests.delete(url, headers=headers))
	except requests.exceptions.RequestException as e:
		print ("[!] Error executing request")

	return

def start_scan(scan_profile, apiKey, secret_key):
	path = "/scans/"+scan_profile+"/"
	req = request(apiKey, secret_key, path, 'POST')
	if req != None:
		print (req.text)

def stop_scan(scan_profile, apiKey, secret_key):
	path = "/scans/"+scan_profile+"/"
	req = request(apiKey, secret_key, path, 'DELETE')
	if req != None:
		print (req.text)
	else:
		print("No scans running" + "\n")

def scan_status(scan_profile, apiKey, secret_key):
	path = "/scans/"+scan_profile+"/"
	req = request(apiKey, secret_key, path, 'GET')
	if req != None:
		print (req.text)

def get_domains(apiKey, secret_key):
	path = "/domains/"
	req = request(apiKey, secret_key, path, 'GET')
	if req != None:
		#print (req.text)
		return json.loads(req.text)


def get_domain_profiles(apiKey, secret_key, domain_token):
	path = "/profiles/"+domain_token+"/"
	req = request(apiKey, secret_key, path, 'GET')
	if req != None:
		print (eval(req.text))


def get_all_profiles(apiKey, secret_key):
	path = "/profiles/"
	req = request(apiKey, secret_key, path, 'GET')
	if req != None:
		return eval(req.text)

def add_scan_profile(apiKey, secret_key, scan_profile):
	path = "/profiles/"

	req = request(apiKey, secret_key, path, 'POST', {
		'endpoint': scanProfile,
		'unique': True
	})
	if req != None:
		print json.dumps(req.text)

def add_scan_profile_csv(apiKey, secret_key):
	path = "/profiles/"
	with open ('profiles.csv', 'rU') as csvfile:
		profilereader = csv.reader(csvfile, delimiter=' ')
		for row in profilereader:
			endpoint=row[0]
			print(endpoint)

			req = request(apiKey, secret_key, path, 'POST', {
				'endpoint': endpoint,
				'unique': True

			})

			if req != None:
				print (req.text)

def update_scan_schedule(apiKey, secret_key,frequency):
	all_profiles=get_all_profiles(apiKey, secret_key)
	for item in all_profiles:
		scanProfile=item["token"]
		path = "/scanschedules/"+scanProfile+"/"
		req = request(apiKey, secret_key, path, 'POST', {
			'frequency': frequency,
		})
		if req != None:
			print(item["endpoint"] + " - scan schedule updated to " + frequency + "\n")

def update_asset_settings(apiKey, secret_key, monitoring):
	all_domains = get_domains(apiKey, secretKey)
	for i in all_domains:
		domainToken=i["token"]
		print(domainToken)
		path="/domains/"+domainToken+"/settings/"
		req = request(apiKey, secret_key, path, 'PUT', {
			'monitoring': monitoring,
			'scrape': monitoring,
			'brute_force': monitoring
		})
		if req != None:
			if monitoring == True:
				status="enabled"
				print(i["name"] + " - Asset Monitoring " + status + "\n")
			elif monitoring == False:
				status="disabled"
				print(i["name"] + " - Asset Monitoring " + status + "\n")


def delete_scan_schedule(apiKey, secret_key):
	all_profiles=get_all_profiles(apiKey, secret_key)
	for item in all_profiles:
		scanProfile=item["token"]
		path = "/scanschedules/"+scanProfile+"/"
		req = request(apiKey, secret_key, path, 'DELETE')
		if req != None:
			 print(item["endpoint"] + " - scan schedule deleted" + "\n")

def add_domain(apiKey, secret_key, domain):
	path = "/domains/"
	req = request(apiKey, secret_key, path, 'POST', {
		'name': domain
	})

	if req != None:
		print (req.text)



def delete_scan_profiles(apiKey, secret_key):
	all_profiles=get_all_profiles(apiKey, secretKey)
	all_profiles
	for item in all_profiles:
		scanProfile=item["token"]
		path="/profiles/"+scanProfile+"/"
		req = request(apiKey, secret_key, path, 'DELETE')
		if req != None:
			print("\n" + item["endpoint"] + " deleted" + "\n")
		else:
			print("There is no scan profiles to delete")


def profiles_scan_status(apiKey, secret_key):
	profiles = get_all_profiles(apiKey, secret_key);
	if profiles != None:
		for scan in profiles:
			#print i["token"]
			scan_status(scan["token"], apiKey, "")


def get_latest_full_report(scan_profile, apiKey, secret_key):
	path="/fullreports/"+scan_profile+"/latest/"
	req = request(apiKey, secret_key, path, 'GET', 'No reports found for scanprofile: '+ scan_profile)
	if req != None:
		return eval(req.text)


def get_findings_for_scan_profile(scan_profile, apiKey, secret_key):
	path = "/findings/" + scan_profile + "/?severity=high&from=" + str(int(time.time()-time_interval*86400)) + "&to=" + str(int(time.time()))
	req = request(apiKey, secret_key, path, 'GET', 'No reports found for scanprofile: ' + scan_profile)
	if req != None:
		return json.loads(req.text)

def get_reports(scan_profile, apiKey, secret_key):
	path = "/reports/" + scan_profile + "/?from=" + str(int(time.time()-time_interval*86400)) + "&to=" + str(int(time.time()))
	req = request(apiKey, secret_key, path, 'GET', 'No reports found for scanprofile: ' + scan_profile)
	if req != None:
		return eval(req.text)

def get_domain_findings(domain, apiKey, secret_key):
	path = "/domains/" + domain + "/findings/" + "?severity=high&from=" + str(
		int(time.time() - 100 * 86400)) + "&to=" + str(int(time.time()))
	req = request(apiKey, secret_key, path, 'GET', 'No reports found for Domain: ' + domain)
	if req != None:
		return eval(req.text)

def contains(list, filter):
	for x in list:
		if filter(x):
			return True
	return False

def remediation_time(apiKey, time_interval, df_full):
	all_profiles = get_all_profiles(apiKey, secretKey)
	if len(all_profiles) < 1:
		print("No scan profiles in team. Aborting.... " + "\n")
	else:
		x = 0
		findings_and_time=[]
		reports_and_time=[]
		for i in range(len(all_profiles)):
			scanProfile = all_profiles[i]["token"]
			scanProfileName=all_profiles[i]["endpoint"]
			print("Checking remediation time for " + scanProfileName + "...")
			response_findings = get_findings_for_scan_profile(scanProfile, apiKey, secretKey)
			for item in response_findings:

				findings_and_time.append({"Scan_profile": all_profiles[i]["endpoint"], "signature": item["signature"], "f_timestamp": item["timestamp"], "title": item["title"], "scanProfileToken": item["scan_profile_token"]})

			response_reports=get_reports(scanProfile, apiKey, secretKey)
			for item in response_reports:
				reports_and_time.append({"scanProfileToken": scanProfile, "r_timestamp": item["created"]})
	if len(reports_and_time) < 1:
		print("\n")
	else:
		df_r = pd.DataFrame(reports_and_time)
		df_f = pd.DataFrame(findings_and_time)
		df=df_r.merge(right=df_f, how="left", on="scanProfileToken")

		df["f_timestamp"] = pd.to_datetime(df["f_timestamp"])
		df["r_timestamp"] = pd.to_datetime(df["r_timestamp"])

		r_df = df[["scanProfileToken", "r_timestamp"]]

		df = df.sort_values(["f_timestamp"])

		def fixing_time(first, last, scanProfile):
			try:
				disappearance_date = next(
					x for x in r_df[r_df["scanProfileToken"] == scanProfile]["r_timestamp"].sort_values() if last < x)
			except StopIteration:
				return None
			else:
				return disappearance_date - first

		def dis_date(last, scanProfile):
			try:
				return next(
					x for x in r_df[r_df["scanProfileToken"] == scanProfile]["r_timestamp"].sort_values() if last < x)
			except StopIteration:
				return None

		df = df.groupby(by=["Scan_profile", "scanProfileToken", "signature", "title"])["f_timestamp"].agg(["first", "last"]).reset_index()
		df["time_diff"] = df.apply(lambda x: fixing_time(x["first"], x["last"], x["scanProfileToken"]), axis=1)
		df["dis_date"] = df.apply(lambda x: dis_date(x["last"], x["scanProfileToken"]), axis=1)
		df_cleaned = df[~pd.isnull(df["time_diff"])]

		df_full = pd.concat([df_full, df_cleaned], ignore_index=True)

		print("Printing findings information to df_full.csv... " + "\n")
		df_full.to_csv("df_full.csv")
		df_full["time_diff"]=pd.to_timedelta(df_full["time_diff"])

		print("Total number of high severity findings that have been remediated: " + str(df_full["title"].count()))
		print("Mean remediation time for all scan profiles: " + str(df_full["time_diff"].mean().days) + " days" )
		print("Max remediation time for all scan profiles: " + str(df_full["time_diff"].max().days) + " days" )
		print("Min remediation time for all scan profiles: " + str(df_full["time_diff"].min().days) + " days" + "\n")
		print("Most remediated finding: " + "\n" + str(df_full["title"].value_counts()) + "\n")


		print(df_full["time_diff"].describe())


def get_dms_findings(apiKey):
	unpatched_high_risks=[]
	patched_high_risks=[]
	patched_high_risks_count=0
	vuln_domain=[]
	total_findings_count=0
	all_domains = get_domains(apiKey, secretKey)
	for i in all_domains:
		domain=i["token"]
		total_findings_per_domain_count=0
		print("Apex domain: " + str(i["name"]))
		response = get_domain_findings(domain, apiKey, secretKey)
		if response is not None:
			for item in response:
				if item != "error":

					a=item["tags"]
					if any(d['value'] == 'patched' for d in a):
						patched_high_risks_count=patched_high_risks_count+1
						patched_high_risks.append(item)

					else:
						unpatched_high_risks.append(item)
						total_findings_count=total_findings_count+1
						total_findings_per_domain_count=total_findings_per_domain_count+1	
				
		else:
			continue
		
		print("Findings for domain: " + str(total_findings_per_domain_count)+ "\n")
		
		if total_findings_per_domain_count > 0:
			vuln_domain.append({"domain": i["name"], "domain_token": domain, "Num_findings": total_findings_per_domain_count})
		else:
			continue

	print("\n" + "Total number of non-patched findings: " + str(total_findings_count)+"\n")

	print("\n" + "Total number of patched findings: " + str(patched_high_risks_count)+"\n")
	
	if len(vuln_domain)>0:
		with open('vuln_domains.json', 'w') as fp:
			json.dump(vuln_domain, fp)
		df1=pd.io.json.json_normalize(unpatched_high_risks)
		df2=pd.io.json.json_normalize(patched_high_risks)

		df1.columns = df1.columns.map(lambda x: x.split(".")[-1]) 
		df2.columns = df2.columns.map(lambda x: x.split(".")[-1])    
	   
		print("Printing to CSVs..:")
		print("{:%Y%m%d-%H%M}_all_UNPATCHED_high_dms_findings.csv".format(today))
		df1=df1[['found_at', 'tags', 'title', 'url', 'description', 'references', 'risk', 'uuid', 'details', 'domain_token']]
		df2=df2[['found_at', 'tags', 'title', 'url', 'description', 'references', 'risk', 'uuid', 'details', 'domain_token']]
		today=pd.Timestamp('today')
		df1.to_csv("{:%Y%m%d-%H%M}_all_UNPATCHED_high_dms_findings.csv".format(today))
		df2.to_csv("{:%Y%m%d-%H%M}_all_PATCHED__high_dms_findings.csv".format(today))
	
	else:
		print()

			
	
	
def start_all_scans(apiKey):
	all_profiles=get_all_profiles(apiKey, secretKey)
	if len(all_profiles) < 1:
		print("No scan profiles in team. Aborting...." + "\n")
	else:
		for item in all_profiles:
			scanProfile=item["token"]
			start_scan(scanProfile, apiKey, secretKey)
			scan_status(scanProfile, apiKey, secretKey)

def stop_all_scans(apiKey):
	all_profiles=get_all_profiles(apiKey, secretKey)
	for item in all_profiles:
		scanProfile=item["token"]
		stop_scan(scanProfile, apiKey, secretKey)
		scan_status(scanProfile, apiKey, secretKey)

def get_subdomains(apiKey, secret_key, domain_token):
	path = "/domains/"+domain_token+"/subdomains/"
	req = request(apiKey, secret_key, path, 'GET')
	if req != None:
		return json.loads(req.text)


def get_all_subdomains(apiKey):
	total_subdomains_count=0
	all_domains = get_domains(apiKey, secretKey)
	all_subs=[]
	for i in all_domains:
		domain=i["token"]
		
		subdomains_per_domain=0
		print("Apex domain: " + str(i["name"]))
		response=get_subdomains(apiKey, secretKey, domain)
		for item in response:
			all_subs.append(item["name"])
			total_subdomains_count=total_subdomains_count+1
			subdomains_per_domain=subdomains_per_domain+1

	df.to_csv("all_subdomains.csv", index=False)



	print("Total number of subdomains: " + str(total_subdomains_count)+ "\n")

def counting_all_scanprofiles(apiKey, teamName):
	scan_profiles=[]
	unverified_count=0
	verified_count=0
	global total_sp_count

	all_scan_profiles=get_all_profiles(apiKey, secretKey)
	for i in range(len(all_scan_profiles)):
		if all_scan_profiles[i]["status"] == "verified":
			print(all_scan_profiles[i]["endpoint"])
			scan_profiles.append(all_scan_profiles[i]["endpoint"])
			verified_count+=1
		else:
			unverified_count+=1
	df=pd.DataFrame(scan_profiles)
	df.to_csv("all_scan_profiles.csv",index=False)
	print("\n" + "Number of verified scan profiles in team " + str(teamName) + ": " + str(verified_count))
	print("Number of unverified scan  profiles in team " + str(teamName) + ": " + str(unverified_count) + "\n")
	total_sp_count.append({"Unverified": unverified_count, "Verified": verified_count})
	return total_sp_count


secretKey = ''
scanProfile = ''

#Specify time interval for remidation time (In days)
time_interval=100


total_sp_count=[]

domainToken = ''
reportToken = ''

action_team=0
action = ''

while True:
	action_team=0
	print("What do you wish to do?")
	print("Specify with opening integer what you wish to do." + "\n")
	print("1. Get all scan profiles")
	print("2. Get all verified domains")
	print("3. Get all DMS findings with high severity")
	print("4. Get all subdomains for my APEX domains")
	print("5. Add new scan profile from text input")
	print("6. Add new profiles from CSV")
	print("7. Add new domain")
	print("8. Starting all scans")
	print("9. Stopping all scans")
	print("10. DELETING all scan profiles")
	print("11. Get info about remediation time for past " + str(time_interval) + " days")
	print("12. Updating scan schedule(s) for scan profiles")
	print("13. Removing scan schedule(s) for scan profiles")
	print("14. Enable/disable Asset Monitoring"+ "\n")





	action = raw_input("Prefered action: ")

	if action == '1':
		verified_count=0
		print("Getting all scan profiles for all teams...." "\n")
		with open('apikeys.csv', 'rU') as csvfile:
			#Skipping the title and first row in CSV
			next(csvfile)
			#Reads from CSV (apikeys.csv) in the same folder
			apireader = csv.reader(csvfile, delimiter=';')
			for row in apireader:
				apiKey = row[1]
				teamName=row[0]
				print("\n"+"TEAM: "+ str(teamName))
				total_sp_count = counting_all_scanprofiles(apiKey, teamName)
			verified=sum(item['Verified'] for item in total_sp_count)
			unverified=sum(item['Unverified'] for item in total_sp_count)
			print("Total number of verified scan profiles: " + str(verified))
			print("Total number of unverified scan profiles: " + str(unverified) + "\n")
	elif action == '2':
		print("Getting all domains...." "\n")
		with open('apikeys.csv', 'rU') as csvfile:
			#Skipping the title and first row in CSV
			next(csvfile)
			#Reads from CSV (apikeys.csv) in the same folder
			apireader = csv.reader(csvfile, delimiter=';')
			for row in apireader:
				apiKey = row[1]
				print(apiKey)
				print("\n"+"TEAM: "+ row[0])
				print("DOMAINS:")
				all_domains = get_domains(apiKey, secretKey,)
				print json.dumps(all_domains, indent=2)

		
	elif action == '3':
		print("Getting all DMS findings with high severity""\n")
		with open('apikeys.csv', 'rU') as csvfile:
			#Skipping the title and first row in CSV
			next(csvfile)
			#Reads from CSV (apikeys.csv) in the same folder
			apireader = csv.reader(csvfile, delimiter=';')
			for row in apireader:
				apiKey = row[1]
				print("\n"+"TEAM: "+ row[0])
				print("DOMAINS:")
				try:
					all_dms_findings = get_dms_findings(apiKey)
					for i in range(len(all_dms_findings)):
						get_dms_findings(apiKey)
				except: 
					print("No DMS findings" "\n")
		continue
	elif action == '4':
		print("Getting subdomains...." "\n")
		with open('apikeys.csv', 'rU') as csvfile:
			#Skipping the title and first row in CSV
			next(csvfile)
			#Reads from CSV (apikeys.csv) in the same folder
			apireader = csv.reader(csvfile, delimiter=';')
			df=pd.read_csv('apikeys.csv', delimiter=';')
			print("To which team do you wish to add the scan profile?")
			x=1
			for row in apireader:
				apiKey = row[1]
				print("\n"+"TEAM: "+ row[0] + " (" + str(x) + ")")
				x=x+1
			while action_team < 1 or action_team > len(df):
				action_team = int(raw_input("Select to which team you want to retreive the subdomains: "))
			get_all_subdomains(df.iloc[action_team-1,1])	
		continue

	elif action == '5':
		print("Adding new scan profile from input" "\n")
		with open('apikeys.csv', 'rU') as csvfile:
			#Skipping the title and first row in CSV
			next(csvfile)
			#Reads from CSV (apikeys.csv) in the same folder
			apireader = csv.reader(csvfile, delimiter=';')
			df=pd.read_csv('apikeys.csv', delimiter=';')
			print("To which team do you wish to add the scan profile?")
			x=1
			for row in apireader:
				apiKey = row[1]
				print("\n"+"TEAM: "+ row[0] + " (" + str(x) + ")")
				x=x+1
			while action_team < 1 or action_team > len(df):
				action_team = int(raw_input("Select to which team you want to add the scan profile by specifying one of the integers: "))
				scanProfile = raw_input("Enter the scan profile you want to add:" + "\n")
				
				continue	
			add_scan_profile(df.iloc[action_team-1,1], secretKey, scanProfile)
			
	elif action == '6':
		print("Adding scan profiles from CSV...." "\n")
		with open('apikeys.csv', 'rU') as csvfile:
			#Skipping the title and first row in CSV
			next(csvfile)
			#Reads from CSV (apikeys.csv) in the same folder
			apireader = csv.reader(csvfile, delimiter=';')
			df=pd.read_csv('apikeys.csv', delimiter=';')
			print("To which team do you wish to add the scan profiles?")
			x=1
			for row in apireader:
				apiKey = row[1]
				print("\n"+"TEAM: "+ row[0] + " (" + str(x) + ")")
				x=x+1
			while action_team < 1 or action_team > len(df):
				action_team = int(raw_input("Select to which team you want to add the scan profiles by specifying one of the integers: "))
				profiles=pd.read_csv("profiles.csv")
				print("\n" + "Profiles.csv contains:" + "\n")
				print(profiles)
				confirm=raw_input("Please confirm that you want to add the above profiles [Y/n] to team (" + str(action_team) + ") :").lower()
				if confirm == 'y':
					add_scan_profile_csv(df.iloc[action_team-1,1], secretKey)
					break
				elif confirm == 'n':
					print("Aborting adding of scan profiles...." + "\n")
				else:
					print("Incorrect input. Expecting Y/n. Aborting...."  + "\n")	

		continue
	elif action == '7':
		print("Adding new domain from input" "\n")
		with open('apikeys.csv', 'rU') as csvfile:
			#Skipping the title and first row in CSV
			next(csvfile)
			#Reads from CSV (apikeys.csv) in the same folder
			apireader = csv.reader(csvfile, delimiter=';')
			df=pd.read_csv('apikeys.csv', delimiter=';')
			print("To which team do you wish to add the domain?")
			x=1
			for row in apireader:
				apiKey = row[1]
				print("\n"+"TEAM: "+ row[0] + " (" + str(x) + ")")
				x=x+1
			
			while action_team < 1 or action_team > len(df):
				action_team = int(raw_input("Select to which team you want to add the domain by specifying one of the integers: "))
				domain = raw_input("Enter which domain you want to add. Remember to not include any subdomains: " + "\n")
				
				continue	
			add_domain(df.iloc[action_team-1,1], secretKey, domain)

			

	elif action == '8':
		print("Starting all scans...")
		with open('apikeys.csv', 'rU') as csvfile:
			#Skipping the title and first row in CSV
			next(csvfile)
			#Reads from CSV (apikeys.csv) in the same folder
			apireader = csv.reader(csvfile, delimiter=';')

			df=pd.read_csv('apikeys.csv', delimiter=';')
			print("For which team do you want to start all scans?")
			x=1
			for row in apireader:
				apiKey = row[1]
				teamName=row[0]
				print("\n"+"TEAM: "+ teamName + " (" + str(x) + ")")
				x+=1
				total_sp_count = counting_all_scanprofiles(apiKey, teamName)
			while action_team < 1 or action_team > len(df):
				action_team = int(raw_input("Select to which team you want to stop the scans by specifying one of the integers: "))	
			start_all_scans(df.iloc[action_team-1,1])
		continue

	elif action == '9':
		print("Stopping all scans...")
		with open('apikeys.csv', 'rU') as csvfile:
			#Skipping the title and first row in CSV
			next(csvfile)
			#Reads from CSV (apikeys.csv) in the same folder
			apireader = csv.reader(csvfile, delimiter=';')

			df=pd.read_csv('apikeys.csv', delimiter=';')
			print("For which team do you wish to stop all scans?")
			x=1
			for row in apireader:
				apiKey = row[1]
				teamName=row[0]
				print("\n"+"TEAM: "+ teamName + " (" + str(x) + ")")
				x+=1
			while action_team < 1 or action_team > len(df):
				action_team = int(raw_input("Select to which team you want to stop the scans by specifying one of the integers in parentheses: "))	
			stop_all_scans(df.iloc[action_team-1,1])
		continue
	elif action == '10':
		print("delete all scan profiles...")
		with open('apikeys.csv', 'rU') as csvfile:
			#Skipping the title and first row in CSV
			next(csvfile)
			#Reads from CSV (apikeys.csv) in the same folder
			apireader = csv.reader(csvfile, delimiter=';')
			df=pd.read_csv('apikeys.csv', delimiter=';')
			print("For which team do you wish to delete all scan profiles?")
			x=1
			for row in apireader:
				apiKey = row[1]
				teamName=row[0]
				print("\n"+"TEAM: "+ teamName + " (" + str(x) + ")")
				total_sp_count = counting_all_scanprofiles(apiKey, teamName)
				x=x+1
				

			while action_team < 1 or action_team > len(df):
				action_team=int(raw_input("Select to which team you want to delete all scan profiles by specifying one of the integers in parentheses: "))
			action_confirm=raw_input("Please confirm that you want to DELETE all scan profiles in team " + str(action_team) + " with 'Y/n': ").lower()

			if action_confirm == "y":
				delete_scan_profiles(df.iloc[action_team-1,1], secretKey)
			else:
				print("Action interrupted. Aborting deletion..." + "\n")
				continue

	elif action == '11':
		print("Getting average remediation time of high severity findings" "\n")
		with open('apikeys.csv', 'rU') as csvfile:
			x=0
			#Skipping the title and first row in CSV
			next(csvfile)
			#Reads from CSV (apiKeys.csv) in the same folder
			apireader = csv.reader(csvfile, delimiter=';')
			df=pd.read_csv('apikeys.csv', delimiter=';')
			print("For which team do you wish to receive the average remediation time?")
			df_full=pd.DataFrame()
			x=1
			for row in apireader:
				apiKey = row[1]
				teamName=row[0]
				print("\n"+"TEAM: "+ teamName + " (" + str(x) + ")")
				total_sp_count = counting_all_scanprofiles(apiKey, teamName)
				x=x+1
				

			while action_team < 1 or action_team > len(df):
				action_team=int(raw_input("Select to which team you want to receive the average remediation time by specifying one of the integers in parentheses: "))
			remediation_time(df.iloc[action_team-1,1], time_interval, df_full)

			continue
			
	elif action == '12':
			print("Updating scan schedule" "\n")
			with open('apikeys.csv', 'rU') as csvfile:
				#Skipping the title and first row in CSV
				next(csvfile)
				#Reads from CSV (apikeys.csv) in the same folder
				apireader = csv.reader(csvfile, delimiter=';')
				df=pd.read_csv('apikeys.csv', delimiter=';')
				print("To which team do you wish to update the scan schedule?")
				x=1
				for row in apireader:
					apiKey = row[1]
					print("\n"+"TEAM: "+ row[0] + " (" + str(x) + ")")
					x=x+1
				

				while action_team < 1 or action_team > len(df):
					action_team = int(raw_input("Select to which team you want to add the domain by specifying one of the integers: "))
					print("Select to which frequency you want to update the scan schedule (starting from today) " + "\n")
					print("Once (1)")
					print("Daily (2)")
					print("Weekly (3)")
					print("Biweekly (4)")
					print("Monthly (5)")

					frequency = int(raw_input("Please select your frequency:" + "\n"))
					
					if frequency == 1:
						frequency = "once"
					elif frequency == 2:
						frequency = "daily"
					elif frequency == 3:
						frequency = "weekly"
					elif frequency == 4:
						frequency = "biweekly"
					elif frequency == 5:
						frequency = "monthly"
					else:
						continue

					continue	
				update_scan_schedule(df.iloc[action_team-1,1], secretKey, frequency)

	elif action == '13':
		print("Removing scan schedule" "\n")
		with open('apikeys.csv', 'rU') as csvfile:
			#Skipping the title and first row in CSV
			next(csvfile)
			#Reads from CSV (apikeys.csv) in the same folder
			apireader = csv.reader(csvfile, delimiter=';')
			df=pd.read_csv('apikeys.csv', delimiter=';')
			print("To which team do you wish to remove the scan schedule?")
			x=1
			for row in apireader:
				apiKey = row[1]
				print("\n"+"TEAM: "+ row[0] + " (" + str(x) + ")")
				x=x+1
			

			while action_team < 1 or action_team > len(df):
				action_team = int(raw_input("Select to which team you want to add the domain by specifying one of the integers: "))
			delete_scan_schedule(df.iloc[action_team-1,1], secretKey)

	elif action == '14':
		print("Enable/disable Asset Monitoring (AM) for your assets. " "\n")
		with open('apikeys.csv', 'rU') as csvfile:
			#Skipping the title and first row in CSV
			next(csvfile)
			#Reads from CSV (apikeys.csv) in the same folder
			apireader = csv.reader(csvfile, delimiter=';')
			df=pd.read_csv('apikeys.csv', delimiter=';')
			print("To which team do you wish to Enable/disable the Asset Monitoring?")
			x=1
			for row in apireader:
				apiKey = row[1]
				print("\n"+"TEAM: "+ row[0] + " (" + str(x) + ")")
				x=x+1
			

			while action_team < 1 or action_team > len(df):
				action_team = int(raw_input("Select to which team you want to change the asset setting: "))
			print("Select if you want to disable or enable Asset Monitoring across all of your assets: " + "\n")
			print("Enable (1)")
			print("Disable (2)")
			setting = int(raw_input("Enter your option: "))
					
			if setting == 1:
				monitoring = True
			elif setting == 2:
				monitoring = False
			update_asset_settings(df.iloc[action_team-1,1], secretKey, monitoring)
		
