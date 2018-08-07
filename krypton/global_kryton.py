#! /usr/bin/env python3
import pwn
import time
import os
import base64

ALPHA='ABCDEFGHIJKLMNOPQRSTUVWXYZ'

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
    f.write(user+b":\t"+flag+b'\n')
    display()
    user=b"krypton"+bytes(str(i),"ascii")

def connexion():
    global flag, host, user, port 
    return pwn.ssh(user, host, password=flag, port=port)

def start():
    global s, sh
    s=connexion()
    sh=s.run('sh')

def end():
    global s, sh, flag, user
    add_flag()
    s.close()

# set variables
f=open("flag.txt","wb")
i=0
host='krypton.labs.overthewire.org'
user=b"krypton"+bytes(str(i),"ascii")
port=2222

cipher=b'S1JZUFRPTklTR1JFQVQ='
flag=base64.b64decode(cipher)

# krypton0
add_flag()

# krypton0 --> krypton1
start()
sh.sendline(b"cat /krypton/krypton1/krypton2 | tr 'A-Za-z' 'N-ZA-Mn-za-m'")
flag=sh.recvline().split(b' ')[-1][:-1]
end()

# krypton1 --> krypton2
start()
sh.sendline(b'mktemp -d')
folder=sh.recvline()[2:-1]
sh.sendline(b'cd '+folder)
sh.sendline('ln -s /krypton/krypton2/keyfile.dat')
sh.sendline(b'echo "A" > filename')
sh.sendline(b'chmod 777 .')
sh.sendline(b'/krypton/krypton2/encrypt filename')
sh.sendline(b'cat ciphertext')
print(sh.recvall())
#end()

# end
f.close()
print ("\n")
print ("\t\t OverTheWire Krypton Passwords")
print ("\n")
os.system('cat flag.txt')
print ("\n")
