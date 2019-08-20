This API script is made in order to help conducting certain actions at scale for the Detectify service. In order to run this script, you need to 1) have an Enterprise license, 2) making sure that your API key (found at https://detectify.com/dashboard/team -> "API Keys" -> "View more") have the correct settings enabled. 

When above is done, you need to update the apikeys.csv with your API key(s) and team name. These should be separated with a semicolon. 

Lastly, this script runs on python 2.7. To run this, run `python general-API-script.py`

Below is a detailed description of what the different functions (1-13) does. 

1. Running option "1" returns a list of your scan profiles in the terminal, together with aggregated data on how many verified and unverified profiles you have in respective team(s). 

2. "2" will return a JSON blob with all of your domains. Here you'll also get some information whether or not the domain is verified, if it's monitored (meaning monitored via DMS), when it was created and its token. Keep in mind that we generate domains in the background when you create scan profiles. This means that creating "bla.example.com" as a scan profile will result adding the same as a domain, even though you have example.com as a verified domain in the tool already.

3. "3" is only available for customers running the Domain Monitoring Service (DMS). This will return information on all of your "High" severity DMS findings in two CSVs - one for Unpatched findings (meaning still open) with the syntax *DATE-TIME_all_UNPATCHED_high_dms_findings.csv*). The other file will return in the same format but for all patched findings (i.e. no longer vulnerable). 

Running option 3 will also create a json file called vuln_domains.json which contains the domain, the domain token and number of DMS findings.

4. This option will return all subdomains for your domains. It will print the domains we check for subdomains in the terminal, then output a csv called "all_subdomains.csv". This could later be used for adding of scan profiles by modifying option "6" below to read from **all_subdomains.csv** instead of **profiles.csv**

5. Here you can add a new scan profile to a specific team via text input in the terminal. Make sure that your CSM has enabled "bypassing of ownership validation" in order to utilise this option. 

6. Within this folder, you'll find a CSV called **profiles.csv**. This is a file that you can manually update with applications (subdomains, domains or IPs) to bulk add them into the Detectify service. Here you'll have to specify to which team you want to add these scan profiles. Keep in mind that the **profiles.csv** file needs to be updated with the subdomains you want to add as scan profiles, separated by new line. 

7. "7" is used to add a domain into the detectify service. Keep in mind to add your apex domain (i.e. no subdomains included) in order to utilise the auto discovery feature.

8. To start all scans for all scan profiles within a team, run option "8". 

9. Same as above, this is used to stopping all scans currently running for a team. 

10. **USE WITH CARE!** This option will DELETE all scan profiles within a team. Once this is run, there's no way of restoring the lost data. 

11. This option will return information about how long it has taken you to remediate high severity findings the last 100 days. The time interval can be updated by changing the variable **time_interval**. You'll get information printed in the terminal containing: number of high severity findings that have been remediated, average number of days the existed as "open" vulnerabilities, max number of days for a open vulnerability, min number of days and the most common high severity findings that have been fixed. 

For more information about the fixed issues, a CSV can be found in this directory called **df_full.csv**. 

12. Running "12" will allow you to update the scan schedule for your scan profiles. 

13. Will remove the scan schedule for all profiles within a team. 

14. This option allow you to enable or disable Asset Monitoring across all of your asset. Note that default setting for this when enabling is to use both brute forcing and scraping. See https://developer.detectify.com/#asset-inventory-manage-asset-settings-put for more information. 