from subprocess import run, PIPE
from Scripts.settings import *


def find_shellshock(silence):
    # test it for shellshock vulnerability
    command = 'env x="() { :; };echo Vulnerable" /bin/bash -c "echo completed"'
    result = run(command, shell=True, stdout=PIPE).stdout.decode()
    if "Vulnerable" in result:
        if not silence:
            output(end="\r")
            output(f"{BG_Red}SHELLSHOCK VULNERABILITY FOUND!{END}\n"
                   f"{YELLOW}By running the following command it was found that this system is vulnerable to arbitrary code injection.\n"
                   f"{LIGHTGRAY + command + END}")
        return True

    else:
        if not silence:
            output(f"{GREEN}No shellshock vulnerability found.\n")
        return False
