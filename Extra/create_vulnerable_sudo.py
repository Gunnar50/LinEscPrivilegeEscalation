import os
import time
import subprocess
# from subprocess import run, PIPE, call

sudo_bins = ['7z', 'ab', 'alpine', 'ansible-playbook', 'aoss', 'apt-get', 'apt', 'ar', 'aria2c', 'arj', 'arp', 'as',
             'ascii-xfr',
             'ascii85', 'ash', 'aspell', 'at', 'atobm', 'awk', 'aws', 'base32', 'base58', 'base64', 'basenc', 'basez',
             'bash',
             'batcat', 'bc', 'bconsole', 'bpftrace', 'bridge', 'bundle', 'bundler', 'busctl', 'busybox', 'byebug',
             'bzip2', 'c89',
             'c99', 'cabal', 'capsh', 'cat', 'cdist', 'certbot', 'check_by_ssh', 'check_cups', 'check_log',
             'check_memory',
             'check_raid', 'check_ssl_cert', 'check_statusfile', 'chmod', 'choom', 'chown', 'chroot', 'cmp', 'cobc',
             'column',
             'comm', 'composer', 'cowsay', 'cowthink', 'cp', 'cpan', 'cpio', 'cpulimit', 'crash', 'crontab', 'csh',
             'csplit',
             'csvtool', 'cupsfilter', 'curl', 'cut', 'dash', 'date', 'dd', 'debugfs', 'dialog', 'diff', 'dig', 'distcc',
             'dmesg',
             'dmidecode', 'dmsetup', 'dnf', 'docker', 'dosbox', 'dpkg', 'dstat', 'dvips', 'easy_install', 'eb', 'ed',
             'efax',
             'emacs', 'env', 'eqn', 'espeak', 'ex', 'exiftool', 'expand', 'expect', 'facter', 'file', 'find', 'fish',
             'flock',
             'fmt', 'fold', 'fping', 'ftp', 'gawk', 'gcc', 'gcloud', 'gcore', 'gdb', 'gem', 'genie', 'genisoimage',
             'ghc', 'ghci',
             'gimp', 'ginsh', 'git', 'grc', 'grep', 'gtester', 'gzip', 'hd', 'head', 'hexdump', 'highlight', 'hping3',
             'iconv',
             'iftop', 'install', 'ionice', 'ip', 'irb', 'ispell', 'jjs', 'joe', 'join', 'journalctl', 'jq',
             'jrunscript', 'jtag',
             'knife', 'ksh', 'ksshell', 'ksu', 'kubectl', 'latex', 'latexmk', 'ld.so', 'ldconfig', 'less', 'lftp', 'ln',
             'loginctl',
             'logsave', 'look', 'ltrace', 'lua', 'lualatex', 'luatex', 'lwp-download', 'lwp-request', 'mail', 'make',
             'man', 'mawk',
             'more', 'mosquitto', 'mount', 'msfconsole', 'msgattrib', 'msgcat', 'msgconv', 'msgfilter', 'msgmerge',
             'msguniq',
             'mtr', 'multitime', 'mv', 'mysql', 'nano', 'nasm', 'nawk', 'nc', 'neofetch', 'nft', 'nice', 'nl', 'nm',
             'nmap', 'node',
             'nohup', 'npm', 'nroff', 'nsenter', 'octave', 'od', 'openssl', 'openvpn', 'openvt', 'opkg', 'pandoc',
             'paste', 'pdb',
             'pdflatex', 'pdftex', 'perf', 'perl', 'perlbug', 'pexec', 'pg', 'php', 'pic', 'pico', 'pidstat', 'pip',
             'pkexec',
             'pkg', 'posh', 'pr', 'pry', 'psftp', 'psql', 'ptx', 'puppet', 'python', 'rake', 'readelf', 'red',
             'redcarpet',
             'restic', 'rev', 'rlwrap', 'rpm', 'rpmdb', 'rpmquery', 'rpmverify', 'rsync', 'ruby', 'run-mailcap',
             'run-parts',
             'rview', 'rvim', 'sash', 'scanmem', 'scp', 'screen', 'script', 'scrot', 'sed', 'service', 'setarch',
             'setfacl',
             'setlock', 'sftp', 'sg', 'shuf', 'slsh', 'smbclient', 'snap', 'socat', 'soelim', 'softlimit', 'sort',
             'split',
             'sqlite3', 'sqlmap', 'ss', 'ssh-keygen', 'ssh-keyscan', 'ssh', 'sshpass', 'start-stop-daemon', 'stdbuf',
             'strace',
             'strings', 'su', 'sysctl', 'systemctl', 'systemd-resolve', 'tac', 'tail', 'tar', 'task', 'taskset',
             'tasksh', 'tbl',
             'tclsh', 'tcpdump', 'tee', 'telnet', 'tex', 'tftp', 'tic', 'time', 'timedatectl', 'timeout', 'tmate',
             'tmux', 'top',
             'torify', 'torsocks', 'troff', 'ul', 'unexpand', 'uniq', 'unshare', 'unzip', 'update-alternatives',
             'uudecode',
             'uuencode', 'valgrind', 'vi', 'view', 'vigr', 'vim', 'vimdiff', 'vipw', 'virsh', 'w3m', 'wall', 'watch',
             'wc', 'wget',
             'whiptail', 'wireshark', 'wish', 'xargs', 'xdotool', 'xelatex', 'xetex', 'xmodmap', 'xmore', 'xpad', 'xxd',
             'xz',
             'yarn', 'yash', 'yum', 'zathura', 'zip', 'zsh', 'zsoelim', 'zypper']

for bin_name in sudo_bins:
    bin_dir = subprocess.run(f"which {bin_name}", shell=True, stdout=subprocess.PIPE).stdout.decode().strip()
    if bin_dir:
        subprocess.call(f"echo 'test ALL=(ALL) {bin_dir}' >> /etc/sudoers", shell=True)



