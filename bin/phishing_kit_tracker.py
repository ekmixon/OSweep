#!/opt/splunk/bin/python
"""
Description: Tracking threat actor emails in phishing kits. 

Source: https://github.com/neonprimetime/PhishingKitTracker

Instructions: None

Rate Limit: None

Results Limit: None

Notes: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""


import time
from collections import OrderedDict
import glob
import os
import shutil
import sys
import zipfile

app_home = f'{os.environ["SPLUNK_HOME"]}/etc/apps/OSweep'
tp_modules = f"{app_home}/bin/_tp_modules"
sys.path.insert(0, tp_modules)
import validators

import commons


date = time.strftime("%Y-%m")
csv  = "https://raw.githubusercontent.com/neonprimetime/PhishingKitTracker/master/{}_PhishingKitTracker.csv"

def get_project():
    """Download the project to /tmp"""
    session = commons.create_session()
    project = "https://github.com/neonprimetime/PhishingKitTracker/archive/master.zip"
    resp    = session.get(project, timeout=180)

    if resp.status_code != 200 or resp.content == "":
        return

    with open("/tmp/master.zip", "wb") as repo:
        repo.write(resp.content)

    repo_zip = zipfile.ZipFile("/tmp/master.zip", "r")
    repo_zip.extractall("/tmp/")
    repo_zip.close()

    # Remove current files
    for csv in glob.glob(f'/{os.environ["SPLUNK_HOME"]}/etc/apps/OSweep/lookups/2*_PhishingKitTracker.csv'):
        os.remove(csv)

    # Add new files
    for csv in glob.glob("/tmp/PhishingKitTracker-master/2*_PhishingKitTracker.csv"):
        shutil.move(csv, f'/{os.environ["SPLUNK_HOME"]}/etc/apps/OSweep/lookups')

    os.remove("/tmp/master.zip")
    shutil.rmtree("/tmp/PhishingKitTracker-master")
    return

def get_feed():
    """Return the latest report summaries from the feed."""
    session   = commons.create_session()
    data_feed = get_file(session)

    if data_feed is None:
        return
    return data_feed

def get_file(session):
    """Return a list of tags."""
    resp = session.get(csv.format(date), timeout=180)

    if resp.status_code == 200 and resp.content != "":
        return resp.content.splitlines()
    return

def write_file(data_feed, file_path):
    """Write data to a file."""
    if data_feed is None:
        return

    with open(file_path, "w") as open_file:
        header = data_feed[0]

        open_file.write(f"{header}\n")

        for data in data_feed[1:]:
            open_file.write(f'{data.encode("UTF-8")}\n')
    return

if __name__ == "__main__":
    if sys.argv[1].lower() == "feed":
        data_feed    = get_feed()
        lookup_path = f"{app_home}/lookups"
        file_path = f"{lookup_path}/{date}_PhishingKitTracker.csv"

        write_file(data_feed, file_path)
    elif sys.argv[1].lower() == "git":
        get_project()
