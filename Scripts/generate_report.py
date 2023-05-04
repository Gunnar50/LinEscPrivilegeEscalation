import re
import sys
from Scripts.settings import *
from io import StringIO
import os
import datetime

html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Assessment and Mitigation Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
        }

        .container {
            width: 80%;
            max-width: 800px;
            margin: 0 auto;
        }

        header {
            background: #007bff;
            color: #fff;
            padding: 20px;
        }

        header h1 {
            margin: 0;
            font-size: 28px;
        }

        header p {
            margin: 0;
            font-size: 0.9rem;
        }

        .main {
            padding: 20px;
        }

        h2 {
            padding-bottom: 1px;
            margin-bottom: 10px;
            font-size: 20px;
        }

        section {
            margin-bottom: 50px;
        }

        ul {
            margin: 5px;
        }

        p {
            margin: 0;
            padding: 0px 8px;
        }

        .section-highlight {
            background-color: #007bff;
            color: #fff;
            padding: 4px 8px;
            border-radius: 3px;
        }
        

        .warning {
            background-color: #dd0000;
            color: #fff;
            padding: 4px 8px;
            border-radius: 3px;
        }

        .safe {
            background-color: #4caf50;
            color: #fff;
            padding: 4px 8px;
            border-radius: 3px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }

        table, th, td {
            border: 1px solid #ddd;
            text-align: left;
            padding: 8px;
        }

        th {
            background-color: #f2f2f2;
            white-space: nowrap;
        }

        tr:nth-child(even) {
            background-color: #f2f2f2;
        }

        h3 {
            margin-bottom: 10px;
        }

        .no-vulnerability {
            font-weight: bold;
            display: none;
        }

        .intro {
            font-size: 1.1em;
            margin-bottom: 20px;
            text-align: justify;
            line-height: 1.5;
        }
        
        table td code {
            display: block;
            background-color: #f8f8f8;
            border-radius: 4px;
            padding: 4px 6px;
            font-family: monospace;
            white-space: pre-wrap;
        }
        
        .hidden {
            display: none;
        }
        
        .red {
            color: #dd0000;
        }

    </style>
</head>
<body>
    <div class="container">
        <header>
           <h1>Linux Privilege Escalation <br>Vulnerability Assessment and Mitigation Report</h1>
           <p>Generated on: <span id='date'></span></p>
        </header>
        <div class="main">
            <div class="intro">
                <p>
                    This document presents the results of our security assessment, organized into sections that focus on specific functions.<br>
                    Each section highlights potential vulnerabilities and their details.<br>
                    If a section heading appears in <span class="warning">RED</span>, it indicates that a vulnerability has been found, and immediate action is recommended.<br>
                    Please refer to the <span class="section-highlight">Recommendations</span> section at the bottom of the report for suggested mitigation strategies and best practices.<br>
                </p>
            </div>  
    

"""

end_template = """

    <!-- RECOMMENDATIONS SECTION -->
    <section id='recommendations'>
    <h2 class='section-highlight'>Recommendations</h2>
        <ul id='recommendations-list'>
    
            <li id='suid-recommendation' class='hidden'>
                <strong>SUID:</strong> Review the necessity of SUID permissions for each listed file and remove SUID bits where appropriate.<br>
                To remove the SUID bits, log into ROOT account and use <code>chmod u-s /path/to/file</code> for each vulnerable binary.
            </li>
    
            <li id='sudo-recommendation' class='hidden'>
                <strong>SUDO:</strong> Restrict user access by removing NOPASSWD access for listed files in the SUDO section, or completely remove SUDO permission if not in use.<br>
                Please note that if a user can use sudo with a password, it does not necessarily indicate a vulnerability. Just ensure that the user has a strong password to maintain security.<br>
                To restrict access to sudoers, log into ROOT account and update the sudoers file using <code>visudo</code> or <code>nano sudoers</code>.
            </li>
    
            <li id='cap-recommendation' class='hidden'>
                <strong>Capabilities:</strong> Revoke unnecessary capabilities from the listed files to reduce potential security risks.<br>
                To remove capabilities granted, log into ROOT account and use <code>setcap -r /path/to/file</code> for each vulnerable binary.
            </li>
    
            <li id='wwf-recommendation' class='hidden'>
                <strong>World-Writable Files:</strong>  Remove world-writable permissions from listed directories to prevent unauthorized access.<br>
                To remove world-writable permissions, log into ROOT account and use <code>chmod o-w /path/to/file</code> for each of the files / directories.
            </li>
    
            <li id='shellshock-recommendation' class='hidden'>
                <strong>ShellShock:</strong> Update Bash and kernel to a patched version (more recent one) and avoid using vulnerable environment variables.
            </li>
    
            <li id='ssh-recommendation' class='hidden'>
                <strong>SSH:</strong> This section is more of a warning, check each file listed in the SSH section.<br>
                You can also disable root login for SSH if is enabled and use sudo instead for elevated privileges, enhancing security.
            </li>
        </ul>
    </section>


</div>
</div>
<script>
        document.getElementById("date").innerHTML = new Date().toLocaleString();
        document.addEventListener('DOMContentLoaded', function() {
            highlightVulnerabilitySection("#suid-table", "#suid-no-vuln", "#suid-recommendation");
            highlightVulnerabilitySection("#sudo-table", "#sudo-no-vuln", "#sudo-recommendation");
            highlightVulnerabilitySection("#cap-table", "#cap-no-vuln", "#cap-recommendation");
            highlightVulnerabilitySection("#wwf-table", "#wwf-no-vuln", "#wwf-recommendation");
            highlightVulnerabilitySection("#shellshock-table", "#shellshock-no-vuln", "#shellshock-recommendation");

            function highlightVulnerabilitySection(tableSelector, noVulnSelector, recommendationSelector) {
                const table = document.querySelector(tableSelector);
                const noVulnMessage = document.querySelector(noVulnSelector);
                const sectionHeader = table.parentElement.querySelector('h2');
                const recommendation = document.querySelector(recommendationSelector);
                if (table && table.rows.length > 1) {
                    sectionHeader.className = 'warning';
                    recommendation.classList.remove('hidden');
                } else {
                    noVulnMessage.style.display = 'block';
                    table.style.display = 'none';
                    sectionHeader.className = 'safe';
                }
            }
            checkAllHidden();
        });
        
        function checkAllHidden() {
            const recommendations = document.querySelectorAll('#recommendations ul li');
            const allHidden = Array.from(recommendations).every(recommendation => recommendation.classList.contains('hidden'));
        
            if (allHidden) {
                const noVulnerabilitiesMessage = document.createElement('li');
                noVulnerabilitiesMessage.textContent = 'No vulnerabilities found in this system!';
                const recommendationsList = document.querySelector('#recommendations ul');
                recommendationsList.appendChild(noVulnerabilitiesMessage);
            }
        }

    </script>
</body>
</html>"""


# writes to the html file
def save_html_to_file(html, file_name):
    # Save HTML to file
    with open(file_name, 'w') as f:
        f.write(html)


def generate_report_name():
    try:
        os.listdir("Reports")
        report_folder = "Reports"
    except FileNotFoundError:
        report_folder = "."

    # Find all the reports in the folder
    reports = [f for f in os.listdir(report_folder) if os.path.isfile(os.path.join(report_folder, f))]

    # Use regular expression to extract the report number from the file name
    report_numbers = [int(re.findall(r'(\d+)_report_\d{2}-\d{2}-\d{4}\.' + "html", report)[0]) for report in reports
                      if re.match(r'\d+_report_\d{2}-\d{2}-\d{4}\.' + "html", report)]

    # Find the last report number and generate the next one
    if len(report_numbers) == 0:
        next_report_number = 1
    else:
        next_report_number = max(report_numbers) + 1

    # Generate the file name for the next report
    return f"{report_folder}/{next_report_number}_report_{datetime.date.today().strftime('%d-%m-%Y')}.html"


def header_info(whoami, shell_users, system_info):
    output(f"<section id='general'>", True)
    output(f"<h2 class='section-highlight'>GENERAL INFORMATION</h2>", True)
    output(f"<p><b>System:</b> {system_info['system']}</p>", True)
    output(f"<p><b>System Release:</b> {system_info['release']}</p>", True)
    output(f"<p><b>System Version:</b> {system_info['version']}</p>", True)
    output(f"<p><b>System Architecture:</b> {system_info['architecture']}</p>", True)
    output(f"<p><b>Current User:</b> {whoami}</p>", True)
    output(f"<p><b>Other Users:</b></p>", True)
    if len(shell_users) > 1:
        output(f"<ul>", True)
        for other_user in shell_users:
            if other_user != whoami:
                output(f"<li>{other_user}</li>", file=True)
        output(f"</ul>", True)
    output("</section>", True)

