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
