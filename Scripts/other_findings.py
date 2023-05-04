#!/usr/bin/python3

from Scripts.settings import *
from subprocess import run, PIPE
import threading

progress = Progress()


def private_keys_search(current_user, silence):
    progress.running = True
    # possible private keys in the system - look in root, home, etc and mnt
    private_keys = []
    for directory in ["/root", f"/home/${current_user}", "/etc", "mnt"]:
        private_keys.append(
            run(f"timeout 50 grep -rl '\\-\\-\\-\\-\\-BEGIN .* PRIVATE KEY.*\\-\\-\\-\\-\\-' {directory} 2>/dev/null",
                shell=True, stdout=PIPE).stdout.decode())

    # if nothing was found in the directories above, then look in the whole system
    if all("" == empty for empty in private_keys):
        private_keys[0] = run(
            f"timeout 100 grep -rl '\\-\\-\\-\\-\\-BEGIN .* PRIVATE KEY.*\\-\\-\\-\\-\\-' / 2>/dev/null", shell=True,
            stdout=PIPE).stdout.decode()

    progress.running = False

    # if anything was found then print out
    if not all("" == empty for empty in private_keys):
        output(end="\r")
        output(f"<strong><p>Possible Private SSH keys found:</p></strong>", True)
        if not silence:
            output(f"{BLUE}Possible private SSH keys found\n{END}")
            output(f"{YELLOW}Have a second look")
        output("<ul>", True)
        for keys in private_keys:
            if keys != "":
                for key in keys.strip().split("\n"):
                    output(f"<li>{key}</li>", True)
                    if not silence:
                        output(RED + key + END)
        output("</ul>", True)


def ssh_rules_agent(silence):
    progress.running = True
    # SSH rules files
    hostsdenied = run("ls /etc/hosts.denied 2>/dev/null", shell=True, stdout=PIPE).stdout.decode()
    hostsallow = run("ls /etc/hosts.allow 2>/dev/null", shell=True, stdout=PIPE).stdout.decode()
    sshconfig = run("ls /etc/ssh/ssh_config 2>/dev/null", shell=True, stdout=PIPE).stdout.decode()

    progress.running = False

    if hostsdenied:
        output(end="\r")
        output("<strong><p>hosts.denied found:</p></strong>", True)
        if not silence:
            output("\n[+] hosts.denied found, trying to reading the rules:")

        read_hosts = '"/etc/hosts.denied" 2>/dev/null | grep -v "#" | grep -Iv "^$"'
        if hosts := run(read_hosts, shell=True, stdout=PIPE).stdout.decode():
            output("<ul>", True)
            for host in hosts.split("\n"):
                output(f"<li>{host}</li>", True)
            output("</ul>", True)

            if not silence:
                output(run(f'{read_hosts} | sed -E "s,.*,{GREEN}&{END},"', shell=True, stdout=PIPE).stdout.decode())

        else:
            output(end="\r")
            output(
                f"<strong><p>No rules found in hosts.denied. Worth looking into <span class='red'>/etc/hosts.denied</span> for anything missed.</p></strong>", True)
            if not silence:
                output(f"\nNo rules found. {YELLOW}Worth looking into /etc/hosts.denied for anything missed.{END}")

    if hostsallow:
        read_hosts = '" /etc/hosts.allow" 2>/dev/null | grep -v "#" | grep -Iv "^$"'

        if not silence:
            output(f"\nhosts.allow found, trying to reading the rules:")
        if hosts := run(read_hosts, shell=True, stdout=PIPE).stdout.decode():
            output("<ul>", True)
            for host in hosts.split("\n"):
                output(f"<li>{host}</li>", True)
            output("</ul>", True)

            if not silence:
                output(run(f'{read_hosts} | sed -E "s,.*,{RED}&{END},"', shell=True, stdout=PIPE).stdout.decode())

        else:
            output("<p><strong>No rules found in hosts.allow. Worth looking into <span class='red'>/etc/hosts.allow</span> for anything missed.</strong></p>",
                   True)
            if not silence:
                output(f"\tNo rules found. {YELLOW}Worth looking into /etc/hosts.allow for anything missed.{END}")

    if sshconfig:
        read_config = r'grep -v "^#"  /etc/ssh/ssh_config 2>/dev/null | grep -Ev "\W+\#|^#" 2>/dev/null | grep -Iv "^$"'

        if config := run(read_config, shell=True, stdout=PIPE).stdout.decode():
            output("<p><strong>Interesting info in /etc/ssh/ssh_config file:</strong></p>", True)
            output("<ul>", True)
            for host in config.split("\n"):
                if host:
                    output(f"<li>{host}</li>", True)
            output("</ul>", True)

            if not silence:
                output(f"\n{YELLOW}Searching inside /etc/ssh/ssh_config for interesting info.{END}")
                output(run(f'\t{read_config} | sed -E "s,Host|ForwardAgent|User|ProxyCommand,{RED}&{END},"', shell=True,
                           stdout=PIPE).stdout.decode())

    # list ssh agents if any
    if run("ssh-add -l 2>/dev/null | grep -qv 'no identities'", shell=True, stdout=PIPE).stdout.decode():
        output("<strong><p>Listing SSH Agents</p></strong>", True)
        if not silence:
            output("Listing SSH Agents")
        output("<ul>", True)
        for agent in run("ssh-add -l", shell=True, stdout=PIPE).stdout.decode().strip().split("\n"):
            if not silence:
                output(agent)
            output(f"<li>{agent}</li>", True)
        output("</ul>", True)


def pam_d_passwords(silence):
    progress.running = True

    # look inside pam.d for passwords, long shot worth trying
    pass_pamd = run('grep -Ri "passwd" /etc/pam.d/ 2>/dev/null | grep -v ":#"', shell=True, stdout=PIPE).stdout.decode()
    progress.running = False
    if pass_pamd:
        output(end="\r")
        output("<strong>Passwords inside pam.d</strong>", True)
        output("<ul>", True)
        for p in run(f'grep -Ri "passwd" /etc/pam.d/ 2>/dev/null | grep -v ":#"', shell=True, stdout=PIPE).stdout.decode():
            output(f"<li>{p}</li>", True)
        output("</ul>", True)

        if not silence:
            output("Passwords inside pam.d")
            output(run(f'grep -Ri "passwd" /etc/pam.d/ 2>/dev/null | grep -v ":#" | sed "s,passwd,{RED + END},', shell=True, stdout=PIPE).stdout.decode())


def result_other_findings(current_user, silence):
    private_keys_search(current_user, silence)
    ssh_rules_agent(silence)
    pam_d_passwords(silence)


def other_findings(current_user, silence):
    progress_thread = CThread(target=lambda: progress.progress_func(silence))
    result_findings_thread = CThread(target=lambda: result_other_findings(current_user, silence))

    progress_thread.start()
    result_findings_thread.start()

    progress_thread.join()
    return result_findings_thread.join()
