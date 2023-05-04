import os
import platform
import sys
import re
import datetime
import threading
import time
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from subprocess import run, PIPE
from io import StringIO
from Scripts.suid_misconfig import find_suid
from Scripts.sudo_misconfig import find_sudo
from Scripts.capabilities import find_capabilities
from Scripts.shellshock import find_shellshock
from Scripts.world_writable_files import find_world_writable_files
from Scripts.other_findings import other_findings
from Scripts.settings import *
from Scripts.generate_report import Tee, html_template, end_template, save_html_to_file, generate_report_name, \
    header_info

start_time = time.time()

banner = """
 /$$       /$$           /$$$$$$$$                
| $$      |__/          | $$_____/                   
| $$       /$$ /$$$$$$$ | $$        /$$$$$$$  /$$$$$$$
| $$      | $$| $$__  $$| $$$$$    /$$_____/ /$$_____/
| $$      | $$| $$  \ $$| $$__/   |  $$$$$$ | $$      
| $$      | $$| $$  | $$| $$       \____  $$| $$      
| $$$$$$$$| $$| $$  | $$| $$$$$$$$ /$$$$$$$/|  $$$$$$$
|________/|__/|__/  |__/|________/|_______/  \_______/
  _____      _       _ _                   ______               _       _   _             
 |  __ \    (_)     (_) |                 |  ____|             | |     | | (_)            
 | |__) | __ ___   ___| | ___  __ _  ___  | |__   ___  ___ __ _| | __ _| |_ _  ___  _ __  
 |  ___/ '__| \ \ / / | |/ _ \/ _` |/ _ \ |  __| / __|/ __/ _` | |/ _` | __| |/ _ \| '_ \ 
 | |   | |  | |\ V /| | |  __/ (_| |  __/ | |____\__ \ (_| (_| | | (_| | |_| | (_) | | | |
 |_|   |_|  |_| \_/ |_|_|\___|\__, |\___| |______|___/\___\__,_|_|\__,_|\__|_|\___/|_| |_|
                               __/ |                                                      
                              |___/                                                                                                                                 
"""
message = "Welcome to LinEsc Privilege Escalation Toolkit!\n" \
          "All the arguments listed bellow are optional, by running with no arguments, all the options are disabled by default."

epilog = """IMPORTANT SECURITY NOTICE:
-------------------------------------
Please use the LinEsc Privilege Escalation Toolkit responsibly and ethically.
This tool is intended for educational purposes, security assessments, and authorized penetration testing only.
Unauthorized use, distribution, or exploitation of this toolkit may result in severe legal consequences.
By using this tool, you agree to adhere to all applicable laws and ethical guidelines.
-------------------------------------
"""

parser = ArgumentParser(description=banner+message, epilog=epilog, formatter_class=RawDescriptionHelpFormatter)
parser.add_argument("-s", "--silence", help="This option will silence the program, no verbose output",
                    action="store_true")
parser.add_argument("-e", "--exploit",
                    help="This option will try to exploit and read the specified file path. If no path is provided "
                         "then it will default to /etc/shadow.\n"
                         "If -e or --exploit option is not provided the script will still give you the command to use.\n"
                         "If you do not want that please use the -s or --silence option",
                    default=False, nargs="?", const="/etc/shadow")
parser.add_argument("-p", "--password",
                    help="This option is to pass a user password for SUDO testing (only recommended for CTFs).\n"
                         "If this option is not provided the script will still try SUDO with no password.",
                    default="", nargs="?")
parser.add_argument("-nr", "--noreport", help="This option will NOT generate a report after the script is done running.\n"
                                              "By default LinEsc generates external report in the HTML format",
                    action="store_true")
parser.add_argument("--suid_only", help="This option will only search for suid escalation", action="store_true")
parser.add_argument("--sudo_only", help="This option will only search for sudo escalation", action="store_true")
parser.add_argument("--cap_only", help="This option will only search for capabilities escalation", action="store_true")

# setup variables based on the arguments provided
args = parser.parse_args()
silence = args.silence
exploit = args.exploit
user_password = args.password
no_report = args.noreport
suid_only = args.suid_only
sudo_only = args.sudo_only
cap_only = args.cap_only
padding = 80

whoami = run("whoami", shell=True, stdout=PIPE).stdout.decode().strip()

# check if the current system is linux
if platform.system() != "Linux":
    output("This script only runs in Linux systems.")
    output("Exiting...")
    sys.exit(0)

# check is the current user running the script is root
if whoami == "root":
    output("You are already ROOT!")
    output("Exiting...")
    sys.exit(0)

# get all system information
system = platform.system()
release = platform.release()
version = platform.version()
architecture = platform.machine()

try:
    with open("/etc/os-release") as f:
        for line in f:
            if line.startswith("PRETTY_NAME"):
                name = line.strip().split('=')[1].strip('"')
            elif line.startswith("VERSION"):
                version_num = line.strip().split("=")[1].strip('"')
                break
        version = f"{version_num} {name}"

except FileNotFoundError:
    pass

system_info = {
    "system": system,
    "release": release,
    "version": version,
    "architecture": architecture
}

current_user = run("whoami 2>/dev/null || echo UserUnknown", shell=True, stdout=PIPE).stdout.decode().strip()

# get the users that can use shell
shell_users = run('cat /etc/passwd 2>/dev/null | grep -i "sh$" | cut -d ":" -f 1', shell=True,
                  stdout=PIPE).stdout.decode().strip().split("\n")

# create grep command with all the users
grep_users = "grep"
for user in shell_users:
    grep_users += f' -e "{user}"'


def update_progress(progress_bar, progress_value):
    # Update the progress bar
    progress_bar[0] = progress_value
    progress_str = f"Progress: {int(progress_value)}% [{'=' * (int(progress_value) // 5)}{' ' * (20 - int(progress_value) // 5)}]"
    output(f"\r{progress_str}", end='', flush=True)

    # Check if all tasks have been completed
    if progress_value >= 100:
        output('\n')
        return


def main():
    search_list = []
    if not any([suid_only, sudo_only, cap_only]):
        search_list = [search_suid, search_sudo, search_capabilities, search_world_writable, search_shellshock,
                       search_other_findings]
        
    if suid_only:
        search_list.append(search_suid)
    if sudo_only:
        search_list.append(search_sudo)
    if cap_only:
        search_list.append(search_capabilities)

    header_info(whoami, shell_users, system_info)

    if silence:
        output()
        output(f"{BLUE}{' Executing in Silent mode ':=^{padding}}{END}\n")
        progress_bar = [0]
        progress_thread = CThread(target=update_progress, args=(progress_bar, 0))
        progress_thread.start()
        progress_thread.join()

    else:
        output(banner)
        output()
        output(f"{BLUE}{' Executing in Verbose mode ':=^{padding}}{END}\n")
        output()

    progress_step = 100 / len(search_list)
    progress_value = 0

    for task in search_list:
        task()

        if silence:
            progress_value += progress_step
            update_progress(progress_bar, progress_value)

    try:
        sys.stdout = sys.stdout.files[0]
    except AttributeError:
        pass
    output_str = output_file.getvalue()

    output(end="\r")
    output(f"{YELLOW}{' Execution Completed ':=^{padding}}\n{END}")

    if not no_report:
        save_html_to_file(html_template + output_str + end_template, generate_report_name())

    end_time = time.time()
    output("Execution time: {:.2f} seconds".format(end_time - start_time))
    sys.exit(0)

# -------------------- SCRIPT END HERE ------------------- #
# -------------- BELLOW ARE ALL THE FUNCTIONS ------------ #

def search_suid():
    # -------------------- SUID ------------------- #
    if not silence:
        output(f"{BLUE}{' Searching for SUID files ':=^{padding}}{END}\n")

    # SUID HTML section #
    output("<section id='suid'>", True)
    output("<h2 class='section-highlight'>SUID RESULT</h2>", True)
    output("<table id='suid-table'>"
           "<thead>"
           "<tr>"
           "<th>Binary Path</th>"
           "<th>Exploit Command</th>"
           "<th>Description</th>"
           "</tr>"
           "</thead>"
           "<tbody>", True)

    vuln_bins = find_suid(grep_users, silence, exploit)
    if vuln_bins is not None and len(vuln_bins) > 0:
        for element in vuln_bins:
            output(f"<tr>"
                   f"<td>{element[0]}</td>"
                   f"<td><code>{element[1]}</code></td>"
                   f"<td>{element[2]}</td>"
                   f"</tr>", True)
    output("</tbody></table>", True)
    output("<p id='suid-no-vuln' class='no-vulnerability'>No SUID vulnerabilities found!</p></section>", True)


def search_sudo():
    # -------------------- SUDO ------------------- #
    if not silence:
        output(f"{BLUE}{' Searching for SUDO ':=^{padding}}{END}\n")

    # SUDO HTML section #
    output("<section id='sudo'>", True)
    output("<h2 class='section-highlight'>SUDO RESULT</h2>", True)

    vuln_bins = find_sudo(whoami, grep_users, silence, exploit, user_password)
    output("<table id='sudo-table'>"
           "<thead>"
           "<tr>"
           "<th>Binary Path</th>"
           "<th>Exploit Command</th>"
           "<th>Description</th>"
           "</tr>"
           "</thead>"
           "<tbody>", True)
    if vuln_bins is not None and len(vuln_bins) > 0:
        for element in vuln_bins:
            output(f"<tr>"
                   f"<td>{element[0]}</td>"
                   f"<td><code>{element[1]}</code></td>"
                   f"<td>{element[2]}</td>"
                   f"</tr>", True)
    output("</tbody></table>", True)
    output("<p id='sudo-no-vuln' class='no-vulnerability'>No SUDO vulnerabilities found!</p></section>", True)


def search_capabilities():
    # -------------------- CAPABILITIES ------------------- #
    if not silence:
        output(f"{BLUE}{' Searching for CAPABILITIES ':=^{padding}}{END}\n")

    # CAPABILITIES HTML section #
    output("<section id='capabilities'>", True)
    output("<h2 class='section-highlight'>CAPABILITIES RESULT</h2>", True)
    output("<table id='cap-table'>"
           "<thead>"
           "<tr>"
           "<th>Binary Path</th>"
           "<th>Exploit Command</th>"
           "<th>Description</th>"
           "</tr>"
           "</thead>"
           "<tbody>", True)
    vuln_bins = find_capabilities(silence)
    if vuln_bins is not None and len(vuln_bins) > 0:
        for element in vuln_bins:
            output(f"<tr>"
                   f"<td>{element[0]}</td>"
                   f"<td><code>{element[1]}</code></td>"
                   f"<td>{element[2]}</td>"
                   f"</tr>", True)
    output("</tbody></table>", True)
    output("<p id='cap-no-vuln' class='no-vulnerability'>No important Capabilities granted found!</p></section>",
           True)


def search_world_writable():
    # -------------------- WORLD-WRITABLE FILES ------------------- #
    if not silence:
        output(f"{BLUE}{' Searching for WORLD WRITABLE FILES ':=^{padding}}{END}\n")

    # WORLD-WRITABLE FILES HTML section #
    output("<section id='world-writable'>", True)
    output("<h2 class='section-highlight'>WORLD-WRITABLE FILES RESULT</h2>", True)
    output("<table id='wwf-table'>"
           "<thead>"
           "<tr>"
           "<th>World-Writable Path/Files</th>"
           "<th>Description</th>"
           "</tr>"
           "</thead>"
           "<tbody>", True)
    vuln_bins = find_world_writable_files(silence, shell_users)
    if vuln_bins is not None and len(vuln_bins) > 0:
        for element in vuln_bins:
            output(f"<tr>"
                   f"<td>{element[0]}</td>"
                   f"<td>{element[1]}</td>"
                   f"</tr>", True)
    output("</tbody></table>", True)
    output("<p id='wwf-no-vuln' class='no-vulnerability'>No World Writable Path/Files found!</p></section>", True)


def search_shellshock():
    # -------------------- SHELLSHOCK ------------------- #
    if not silence:
        output(f"{BLUE}{' Searching for SHELLSHOCK vulnerability ':=^{padding}}{END}\n")

    # SHELLSHOCK HTML section #
    shellshock = find_shellshock(silence)
    output("<section id='shellshock'>", True)
    output("<h2 class='section-highlight'>SHELLSHOCK RESULT</h2>", True)
    output("<table id='shellshock-table'>"
           "<thead>"
           "<tr>"
           "<th>Shellshock Vulnerable</th>"
           "<th>Description</th>"
           "</tr>"
           "</thead>"
           "<tbody>", True)
    if shellshock:
        output(f"<tr>"
               f"<td>Yes!</td>"
               f"<td>Shellshock is a security vulnerability in the Bash shell that allows attackers to execute arbitrary code on a target system.</td>"
               f"</tr>", True)

    output("</tbody></table>", True)
    output("<p id='shellshock-no-vuln' class='no-vulnerability'>No Shellshock Vulnerability found!</p></section>",
           True)


def search_other_findings():
    # -------------------- OTHER FINDINGS ------------------- #
    if not silence:
        output(f"{BLUE}{' Searching for Extra findings ':=^{padding}}{END}\n")

    # SHELLSHOCK HTML section #
    output("<section id='other'>", True)
    output("<h2 class='section-highlight' style='background-color: #f48a20;'>OTHER FINDINGS RESULT</h2>", True)
    other_findings(current_user, silence)


if __name__ == "__main__":
    main()
