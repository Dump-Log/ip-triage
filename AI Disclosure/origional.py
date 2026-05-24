# IP intelligence gatherer

# Uses api's to common IP reputation sites to collect and present information
# takes an IP, either fanged, or defanged
# returns results and the urls's to go directly to them

# API documentation
#   AbuseIPDB: https://docs.abuseipdb.com/?python#introduction
#   Virus Total: https://docs.virustotal.com/reference/ip-info\

# Populate the API keys for the two services here
VirusTotalApiKey = ""
AbuseIPDB = ""

import requests
import sys
from concurrent.futures import ThreadPoolExecutor

def fangIP(ip):
    return ip.replace('[.]', '.')

def virusTotal(ip):
    # holds results
    virustotal = {}

    #address for ip info
    ipurl = "https://www.virustotal.com/api/v3/ip_addresses/"+ip

    #address for comments
    commenturl = "https://www.virustotal.com/api/v3/ip_addresses/"+ip+"/comments?limit=20"

    headers = {
        "accept": "application/json",
        "x-apikey": VirusTotalApiKey
    }
    ipresponse = requests.get(ipurl, headers=headers)
    commentresponse = requests.get(commenturl, headers=headers)
    #gui url
    virustotal["url"] = "https://www.virustotal.com/gui/ip-address/"+ip

    if ipresponse.status_code == 200:
        data = ipresponse.json()
        virustotal["ASN"] = data['data']['attributes']['asn']
        virustotal["country"] = data['data']['attributes']['country']
        virustotal["Votes"] = data['data']['attributes']['total_votes']
        virustotal["Analysis"] = data['data']['attributes']['last_analysis_stats']

    if commentresponse.status_code == 200:
        data = commentresponse.json()
        if not data['meta']['count']:
            virustotal["Comments"] = data['data']
        else:
            virustotal["Comments"] = ["No Comments"]

    return virustotal

def abuseIPDB(ip):
    abuseipdb = {}

    # Defining the api-endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '365'
    }

    headers = {
        'Accept': 'application/json',
        'Key': AbuseIPDB
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    response1 = response.json()
    # Formatted output
    abuseipdb['ConfidenceScore'] =  response1['data']['abuseConfidenceScore']
    abuseipdb['isTor'] =response1['data']['isTor']
    abuseipdb['isp'] =response1['data']['isp']
    abuseipdb['totalReports'] =response1['data']['totalReports']
    abuseipdb['usageType'] =response1['data']['usageType']
    abuseipdb['Country'] = response1['data']['countryCode']
    abuseipdb['url'] ="https://www.abuseipdb.com/check/"+ip

    # return results
    return abuseipdb

def ciscogen(ip):
    cisco = {}
    cisco['url'] = "https://www.talosintelligence.com/reputation_center/lookup?search="+ip
    return cisco

def printData(vt_results,abuse_results,c_results):
    print(vt_results['url'],
          "\n\tASN",vt_results['ASN'],
          "\n\tCountry:",vt_results['country'],
          "\n\tVotes",vt_results['Votes'],
          "\n\tAnalysis",vt_results['Analysis'],
          "\n\tComments",vt_results['Comments'])

    print(abuse_results['url'],
          "\n\tConfidenceScore:",abuse_results['ConfidenceScore'],
          "\n\tCountry", abuse_results['Country'],
          "\n\tISP:",abuse_results['isp'],
          "\n\tUse Type:",abuse_results['usageType'],
          "\n\tTor:",abuse_results['isTor'],
          "\n\tTotalReports:",abuse_results['totalReports'])

    print(c_results['url'])


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    ip = sys.argv[1]
    ip = fangIP(ip)


    with ThreadPoolExecutor(max_workers=3) as executor:
        f1 = executor.submit(virusTotal,ip)
        f2 = executor.submit(abuseIPDB,ip)
        f3 = executor.submit(ciscogen,ip)

    # features block until all are received
    vt_results = f1.result()
    abuse_results = f2.result()
    c_results = f3.result()

    # prints results
    printData(vt_results,abuse_results,c_results)
