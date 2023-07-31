import masscan
import pandas as pd
import os
import requests
import json
from datetime import date
import sys

# permanent variables settings
abuse_api = sys.argv[1]
destination_srv = sys.argv[2]
ips_list = ['8.8.8.8/32']

# setting up requests
headers = {
    'Accept': 'application/json',
    'Key': abuse_api
}
url = 'https://api.abuseipdb.com/api/v2/check'
mas = masscan.PortScanner()
mas.scan(ips_list, ports='22,23,443,80,5432,3301,3389,3306,9002,5986,8443,27017,139,137,514,111,7077,5601,9300,8080'
         , arguments='--max-rate 1000')


# cleaning and optimizing JSON
def json_cleaning():
    scanned = []
    for entry in mas.scan_result['scan']:
        ports = []
        for proto in mas.scan_result['scan'][entry]:
            for port in mas.scan_result['scan'][entry][proto]:
                ports.append(port)
            if 1:
                cloud = 'cloud'
            scanned.append({'ipaddress': entry, 'ports': ports, "cloud": cloud, 'lastRep': str(), 'totalRep': int(), 'badRep': int()})
    print(scanned)
    abuse(scanned)


def abuse(scanned):
    count = 0
    for i in scanned:
        ip = i.get('ipaddress')
        querystring = {
            'ipAddress': '{}'.format(ip),
            'maxAgeInDays': '10'
        }
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        decoded_response = json.loads(response.text)
        sample_data = decoded_response.get('data')
        abuse_data = {'badRep': sample_data.get('abuseConfidenceScore'), 'lastRep': sample_data.get('lastReportedAt'), 'totalRep': sample_data.get('totalReports')}
        scanned[count].update(abuse_data)
        count += 1
    create_json(scanned)
    create_csv(scanned)


# write JSON locally
def create_json(results):
    with open('scan_result_test.json', 'w') as outfile:
        for i in results:
            outfile.write(str(i).replace('\'', '\"') + '\n')


# creates backup CSV
def create_csv(results):
    today = date.today()
    ips = []
    ports = []
    reputation = []
    for i in results:
        ips.append(i.get('ipaddress'))
        ports.append(str(i.get('ports')).strip('[]'))
        reputation.append(str(i.get('reputation')))
    df = pd.DataFrame()
    df["IPs"] = ips
    df["Ports"] = ports
    df['Reputation'] = reputation
    df.to_csv('scanned_{}.csv'.format(today.strftime("%d-%m-%Y")))


def scp_forward():
    os.system('scp scan_result.json {}:~'.format(destination_srv))


json_cleaning()
