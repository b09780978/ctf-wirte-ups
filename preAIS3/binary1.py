#!/usr/bin/env python
import binascii

encrypted = binascii.unhexlify("CA7093C8067F23A1E0482A39AE54F279F2848B05A2521929C454AAF0CA")
flag = ""

for i, c in enumerate(encrypted):
    for letter in xrange(0x20, 0x7f):
        if ((((i ^ letter) << ((i ^ 9) & 3)) | ((i ^ letter) >> (8 - ((i ^ 9) & 3)))) + 8 ) & 0xff == ord(c):
            flag += chr(letter)
            break
print flag
