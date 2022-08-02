#!/opt/splunk/bin/python
"""
Description: Use Malshare to gather hashes of potentially malicious files. The 
script accepts a list of strings (domains, IPs, MD5, or SHA256):
    | malshare $ioc$

or input from the pipeline (any field where the value is a domain, IP, MD5 or 
SHA256). The first argument is the name of one field:
    <search>
    | fields <IOC_FIELD>
    | malshare <IOC_FIELD>

Source: https://malshare.com/

Instructions:
1. Switch to the Malshare dashboard in the OSweep app.
2. Add the list of IOCs to the "Domain, IP, MD5, SHA256 (+)" textbox.
4. Click "Submit".

Rate Limit: None

Results Limit: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""


import json
import os
import re
import sys

app_home = f"{os.environ['SPLUNK_HOME']}/etc/apps/OSweep"
tp_modules = f"{app_home}/bin/_tp_modules"
sys.path.insert(0, tp_modules)
import validators

import commons


api = "https://malshare.com/api.php?api_key={}&action=search&query={}".lower()

def process_iocs(results):
    """Return data formatted for Splunk from Malshare."""
    if results is None:
        provided_iocs = sys.argv[1:]

    else:
        provided_iocs = [y for x in results for y in x.values()]
    session = commons.create_session()
    api_key = commons.get_apikey("malshare")
    splunk_table = []

    for provided_ioc in set(provided_iocs):
        provided_ioc = commons.deobfuscate_string(provided_ioc)
        provided_ioc = provided_ioc.lower()

        if (
            not validators.ipv4(provided_ioc)
            and not validators.domain(provided_ioc)
            and not re.match("^[a-f\d]{32}$", provided_ioc)
            and not re.match("^[a-f\d]{64}$", provided_ioc)
        ):
            splunk_table.append({"invalid": provided_ioc})
            continue

        ioc_dicts = query_malshare(provided_ioc, api_key, session)

        splunk_table.extend(iter(ioc_dicts))
    session.close()
    return splunk_table

def query_malshare(provided_ioc, api_key, session):
    """Query Malshare using the provided IOC return data as an dictonary."""
    ioc_dicts = []

    resp = session.get(api.format(api_key, provided_ioc), timeout=180)

    if resp.status_code == 200 and resp.content != '':
        content = re.sub("^", "[", resp.content.decode("UTF-8"))
        content = re.sub("$", "]", content)
        content = json.loads("{}".format(content.replace("}{", "},{")))
    else:
        ioc_dicts.append({"no data": provided_ioc})
        return ioc_dicts

    for data in content:
        ioc_dict = {"md5": data.get("md5", None)}
        ioc_dict["sha256"] = data.get("sha256", None)
        ioc_dict["type"]   = data.get("type", None)
        ioc_dict["added"]  = data.get("added", None)
        ioc_dict["source"] = data.get("source", None)
        ioc_dicts.append(ioc_dict)
    return ioc_dicts

if __name__ == "__main__":
    current_module = sys.modules[__name__]
    commons.return_results(current_module)
