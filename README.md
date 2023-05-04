# LinEsc - Linux Privilege Escalation Toolkit

**LinEsc is a toolkit that search for possible ways to escalate privileges on Linux hosts.**

## Quick Start
To use this script, the only installation requirement is having Python 3 or higher installed. No
other dependencies are necessary since the script utilises libraries that are already included
in Python 3.

Clone the project folder form GitHub
```bash
# From github
git clone https://github.com/Gunnar50/PenTestTool
```

Or simply import the project folder into the vulnerable machine.

As this is a privilege escalation tool, ensure you are running it with an ordinary user (not root).

Check the help section by running the script with a “-h” flag for help.
```bash
python3 LinEsc.py -h
```


## Basic Information

The aim of this toolkit is to search for possible **Privilege Escalation Paths**.

This script does not need any external dependencies, unless you want to contribute.

It uses **/bin/sh** syntax, and commands from Linux systems.

By default, **LinEsc will not write anything to disk and will not try to exploit any vulnerability**.

The script can be executed with no flags to perform a default scan, which will search for
potential vulnerabilities in the system by running all available scripts. Any vulnerability
discovered will be highlighted in the output and the corresponding commands that could
result in privilege escalation for the current user will be displayed, as well as writing to a external report.

**Options:**
- **-s, --silence** - This option will silence the program, no verbose output
- **-e, --exploit** - This option will try to **exploit** and read the specified file path. If no path is provided then it will default to /etc/shadow.  
                      &emsp;&emsp;&emsp;&emsp;&emsp;&emsp; If -e or --exploit option is not provided the script will still give you the command to use.  
                      &emsp;&emsp;&emsp;&emsp;&emsp;&emsp; If you do not want that please use the -s or --silence option.
- **-p, --password** - This option is to pass a user password for that is used in `sudo -l` (only recommended for CTFs).  
                      &emsp;&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;If this option is not provided the script will still try SUDO with no password.
- **-nr, --noreport** - This option will NOT generate a report after the script is done running. By default LinEsc generates external report in the HTML format.
- **--suid_only** - This option will only search for suid escalation.
- **--sudo_only** - This option will only search for sudo escalation.
- **--cap_only** - This option will only search for capabilities escalation.


## Techinical Information

### Functional Requirements
**1. Identifying Potential Vulnerabilities:**
- **Sudo Misconfiguration:** The script searches for binaries in the system that the current user can use with elevated
privileges. It first executes the command sudo -l and checks if any binaries can be executed
with Sudo. If a password is provided, it will attempt to execute the command with Sudo
and the provided password.
You may enable other flags such as -e or –exploit that can
be used to attempt to exploit the system by running commands to get a root shell or read
a specified file path. However, it is only **recommended for training purposes** and is off by default.

- **Suid Misconfiguration:** To detect SUID misconfig, the script uses the command `find / -perm -4000 2>/dev/null` to
search for binaries with the SUID bit set. The script then searches each SUID binary in the dictionary database of vulnerable binaries,
and if a binary is found to be exploitable, it displays a message.
The flags -e or –exploit may be used to activate automatic exploitation **(only recommended for CTFs)**.

- **Capabilities Misconfiguration:**  The capability script searches for binaries that have capabilities granted
using the command `getcap -r / 2>/dev/null` and similar to Sudo and Suid, it searches through the database to see if any found binaries are vulnerable.

- **World-Writable files:** The script uses the `os` module to search for files or directories that have
world-writable permissions. The result is a list of files and directories with world-writable
permissions.
The script then displays a message with all the results, which the user can review and
assess the potential vulnerabilities. It is important to note that not all world-writable files
or directories are necessarily a vulnerability, so further investigation might be needed to
determine if any action is required.

**2. Report Generation:**
After the vulnerability scan is completed, the script will automatically generate an HTML,
userfriendly report in a clear and concise format. The report will provide a summary of
the vulnerabilities discovered, along with a description of each vulnerability and suggested
actions to mitigate the vulnerability.

**3. Compatibility with multiple Linux distributions:**
The toolkit needs to be compatible with a wide range of Linux distributions and their various versions to ensure its effectiveness and usefulness to companies that may use different
distributions. To meet this requirement, the toolkit will be developed using Python3, which
is a platform-independent language. The toolkit will also use libraries and frameworks such
as Threading, Subprocess, and Argparse, which are compatible with multiple Linux distributions.

## Advisory

Please use the LinEsc Privilege Escalation Toolkit responsibly and ethically.
This tool is intended for educational purposes, security assessments, and authorized penetration testing only.
Unauthorized use, distribution, or exploitation of this toolkit may result in severe legal consequences.
By using this tool, you agree to adhere to all applicable laws and ethical guidelines.

