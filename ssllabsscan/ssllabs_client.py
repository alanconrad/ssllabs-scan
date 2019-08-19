'''
See APi doc: https://github.com/ssllabs/ssllabs-scan/blob/stable/ssllabs-api-docs.md
'''
from datetime import datetime
import json
import os
import requests
import time
import ssllabsscan.main as m

API_URL = "https://api.ssllabs.com/api/v2/analyze"

CHAIN_ISSUES = {
    "0": "none",
    "1": "unused",
    "2": "incomplete chain",
    "4": "chain contains unrelated or duplicate certs",
    "8": "chain but the order is incorrect",
    "16": "contains a self-signed root certificate",
    "32": "chain but can't be validated"
}

# Forward secrecy protects past sessions against future compromises of secret keys or passwords.
FORWARD_SECRECY = {
    "0": "No WEAK",
    "1": "With some browsers WEAK",
    "2": "With modern browsers",
    "3": "Yes, with modern browsers",
    "4": "Yes (with most browsers) ROBUST"
}

PROTOCOLS = [
    "TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0 INSECURE", "SSL 2.0 INSECURE"
]

VULNERABLES = [
    "Vuln Beast", "Vuln Drown", "Vuln Heartbleed", "Vuln FREAK",
    "Vuln openSsl Ccs", "Vuln openSSL LuckyMinus20", "Vuln POODLE", "Vuln POODLE TLS"
]

SUMMARY_COL_NAMES = [
    "Host", "Grade", "Hidden Grade", "Owner", "HasWarnings", "Cert Issuer", "Cert Expiry", "Chain issues", 
    "Perfect Forward Secrecy", "Heartbeat ext", "Hostname", "Protocol", "Server signature", "HTTP Status Code", 
    "Signature algorithm"
] + VULNERABLES + PROTOCOLS


class SSLLabsClient():
    def __init__(self, check_progress_interval_secs=10):
        self.__check_progress_interval_secs = check_progress_interval_secs

    '''
    Write scanned results to server's own json file
    '''
    def analyze(self, host, summary_csv_file, owner):
        data = self.start_new_scan(host=host)
        # Removes everything after & including the '/' character in URLs as '/' cannot be in file names
        host = host.split('/')[0]
        # Check if 'json_data' directory exists before writing to it
        if os.path.exists(os.path.join(m.PATH, 'json_data')):
            json_file = os.path.join(os.path.join(m.PATH, "json_data"), f"{host}.json")
        else:
            os.makedirs(os.path.join(m.PATH, 'json_data'))
            p = os.path.join(m.PATH, 'json_data')
            json_file = os.path.join(p, f"{host}.json")
        # Dump JSON
        with open(json_file, "w") as outfile:
            json.dump(data, outfile, indent=2)
        print('JSON dumped successfully.')
        # write the summary to file
        self.append_summary_csv(summary_csv_file, host, data, owner)

    '''
    Run a SSLLABS scan on a server
    '''
    def start_new_scan(self, host, publish="off", startNew="on", all="done", ignoreMismatch="on"):
        path = API_URL
        payload = {
            "host": host,
            "publish": publish,
            "startNew": startNew,
            "all": all,
            "ignoreMismatch": ignoreMismatch
        }
        results = self.request_api(path, payload)
        payload.pop("startNew")
        while results["status"] != "READY" and results["status"] != "ERROR":
            time.sleep(self.__check_progress_interval_secs)
            results = self.request_api(path, payload)
        return results

    '''
    Takes in bit value representing number of flags in a host's chain issues
    Unpacks the bit values and returns list of issues
    '''
    def get_chain_issues(self, val):
        result = []
        val = int(val)
        # If host has 0 issues
        if val == 0:
            result = CHAIN_ISSUES[str(0)]
            return result
        if val & (1 << 0):
            result.append(CHAIN_ISSUES[str(1)])
        if val & (1 << 1):
            result.append(CHAIN_ISSUES[str(2)])
        if val & (1 << 2):
            result.append(CHAIN_ISSUES[str(4)])
        if val & (1 << 3):
            result.append(CHAIN_ISSUES[str(8)])
        if val & (1 << 4):
            result.append(CHAIN_ISSUES[str(16)])
        if val & (1 << 5):
            result.append(CHAIN_ISSUES[str(32)])
        result = ' AND '.join(result)
        return result

    '''
    Access API
    '''
    @staticmethod
    def request_api(url, payload):
        response = requests.get(url, params=payload)
        return response.json()

    '''
    Converts epoch time to readable time format
    '''
    @staticmethod
    def prepare_datetime(epoch_time):
        # SSL Labs returns an 13-digit epoch time that contains milliseconds, Python only expects 10 digits (seconds)
        return datetime.utcfromtimestamp(float(str(epoch_time)[:10])).strftime("%Y-%m-%d")

    '''
    Summarize all json data into html file
    '''
    def append_summary_csv(self, summary_file, host, data, owner):
        # write the summary to file
        with open(os.path.join(m.PATH, summary_file), "a") as outfile:
            proto = data['protocol']
            for dep in data['endpoints']:
                # Some servers don't have a serverSignature field in their .JSON
                try:
                    server_sig = dep["details"]["serverSignature"]
                except:
                    server_sig = "N/A"
                try:
                    chain_issues = self.get_chain_issues(str(dep["details"]["chain"]["issues"]))
                except:
                    chain_issues = "N/A"
            for ep in data["endpoints"]:
                # see SUMMARY_COL_NAMES
                summary = [
                    host,
                    ep["grade"],
                    ep['gradeTrustIgnored'],
                    owner,
                    ep["hasWarnings"],
                    ep["details"]["cert"]["issuerLabel"],
                    self.prepare_datetime(ep["details"]["cert"]["notAfter"]),
                    chain_issues,
                    FORWARD_SECRECY[str(ep["details"]["forwardSecrecy"])],
                    ep["details"]["heartbeat"],
                    ep["serverName"],
                    proto,
                    server_sig,
                    ep["details"]["httpStatusCode"],
                    ep["details"]["cert"]["sigAlg"],
                    ep["details"]["vulnBeast"],
                    ep["details"]["drownVulnerable"],
                    ep["details"]["heartbleed"],
                    ep["details"]["freak"],
                    False if ep["details"]["openSslCcs"] == 1 else True,
                    False if ep["details"]["openSSLLuckyMinus20"] == 1 else True,
                    ep["details"]["poodle"],
                    False if ep["details"]["poodleTls"] == 1 else True,
                ]
                for protocol in PROTOCOLS:
                    found = False
                    for p in ep["details"]["protocols"]:
                        if protocol.startswith(f"{p['name']} {p['version']}"):
                            found = True
                            break
                    summary += ["Yes" if found is True else "No"]
                outfile.write(",".join(str(s) for s in summary) + "\n")