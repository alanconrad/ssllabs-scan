
import csv
import os
import shutil
import sys
import traceback
import time
import fnmatch
import shutil

from ssllabsscan.report_template import REPORT_HTML
from ssllabsscan.ssllabs_client import SSLLabsClient, SUMMARY_COL_NAMES

START_TIME = time.time()
SUMMARY_CSV = "summary.csv"
SUMMARY_HTML = "summary.html"
VAR_TITLE = "{{VAR_TITLE}}"
VAR_DATA = "{{VAR_DATA}}"
DEFAULT_TITLE = "SSL Labs Analysis Summary Report"
DEFAULT_STYLES = "styles.css"
T = time.localtime()
TIMESTAMP = time.strftime('%b-%d-%Y_%H%M', T)
PATH = 'scan-' + TIMESTAMP

'''
Creates html summary report of scanned web servers
'''
def output_summary_html(input_csv, output_html):
    print("\nCreating {} ...".format(output_html))
    data = ""
    with open(os.path.join(PATH, input_csv), "r") as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row[0].startswith("#"):
                data += "<tr><th>{}</th></tr>".format('</th><th>'.join(row))
            else:
                data += '<tr class="{}"><td>{}</td></tr>'.format(row[1][:1], '</td><td>'.join(row))
    # Replace the target string
    content = REPORT_HTML
    content = content.replace(VAR_TITLE, DEFAULT_TITLE)
    content = content.replace(VAR_DATA, data)
    # Write the file out again
    with open(os.path.join(PATH, output_html), "w") as file:
        file.write(content)
    # copy styles.css
    styles_css = os.path.join(PATH, DEFAULT_STYLES)
    if not os.path.exists(styles_css):
        shutil.copyfile(os.path.join(os.path.dirname(__file__), DEFAULT_STYLES), styles_css)

'''
Runs scans on each server
'''
def process(server_list_file, check_progress_interval_secs=15,
        summary_csv=SUMMARY_CSV, summary_html=SUMMARY_HTML):
    # Open input file to read in servers / owners
    with open(server_list_file) as f:
        content = f.readlines()
    # Parse through to gather list of servers and owners
    servers = get_servers(server_list_file, content)
    owners = get_owners(server_list_file, content)
    if not os.path.exists(PATH):
        os.makedirs(PATH)
    with open(os.path.join(PATH, SUMMARY_CSV), "w") as outfile:
        # write column names to file
        outfile.write("#{}\n".format(",".join(str(s) for s in SUMMARY_COL_NAMES)))
    not_scannable = []
    not_scannable_owners = []
    index = 0
    ret = 0
    # Scanning process of servers
    for server in servers:
        try:
            print("Start analyzing {} ...".format(server))
            SSLLabsClient(check_progress_interval_secs).analyze(server, summary_csv, owners[index])
        # If error occurs, add server to list of not scanned servers
        except Exception as e:
            not_scannable.append(server)
            not_scannable_owners.append(owners[index])
            print("Error! Server unable to be scanned.")
            ret = 1
        index += 1
        elapsed_time = time.time() - START_TIME
        print('Elapsed time:', elapsed_time, '\n')
        print("Number of scans attempted:", index)
    # Writes servers that weren't able to be scanned to separate file
    with open(os.path.join(PATH, 'not_scanned.txt'), 'w') as not_scanned:
        index = 0
        for s in not_scannable:
            not_scanned.write(s + ' ' + not_scannable_owners[index] + '\n')
            index += 1
    # Output html summary
    output_summary_html(summary_csv, summary_html)
    return ret

'''
Returns list of servers from the input file
'''
def get_servers(server_list_file, content):
    servers = []
    for server in content:
        server = server.split()[0]
        # Slices of https:// part of url as well as the / url's sometimes end in
        # for some reason, the script will not work otherwise
        if server[-1] == '/':
            server = server[:-1]
        if server.startswith('https://'):
            server = server[8:]
        elif server.startswith('http://'):
            server = server[7:]
        servers.append(server)
    return servers

'''
Returns list of owners from the input file
'''
def get_owners(server_list_file, content):
    with open(server_list_file) as f:
        content = f.readlines()
    owners = []
    for i in content:
        owner = i.strip()
        # Handles both tab and empty space characters in between server host & owner
        try:
            if '\t' in owner:
                owner = i.split('\t', 1)[1]
            else:
                owner = i.split(' ', 1)[1]
            # Check if server host has an owner attached
            if len(owner) > 1:
                # Remove \n at the end of the owner if it is present
                if '\n' in owner:
                    owner = owner[:-1]
                owners.append(owner)
        # Add 'N/A' to owner if it does not exist in the input file
            else:
                owners.append('N/A')
        except:
            owners.append('N/A')
    return owners

'''
Entry point of the script
'''
def main():
    if len(sys.argv) != 2:
        print("{} [SERVER_LIST_FILE]".format(sys.argv[0]))
        return 1
    print("Starting...\n")
    return process(server_list_file=sys.argv[1])


if __name__ == "__main__":
    sys.exit(main())