"""
CS547 Homework SHA3_512 Encryption : 20193577 Hyewon Jeong (2019.10.01.)

===============
Homework Report
===============

SHA3-512 Encryption was tested with hashlib 


References
1. https://github.com/bozhu/AES-Python (Original Implementation by Bo Zhu (http://about.bozhu.me))
2. https://github.com/boppreh/aes (Original Implementation by Lucas Boppre (http://boppreh.com))
"""

#import math
import hashlib
from Crypto.Hash import SHA3_512
from bitarray import bitarray
from hexhamming import hamming_distance

def string2bits(s: str=""):
	return "".join(format(ord(i), "b").zfill(8) for i in s)

print("\n=============================================")
print("Generating 1024 bytes (8192 bits) of all zeros")
print("================================================\n")

hashinput1 = bytearray(1024) 
hashinput2 = bytearray(1024) 
hashinput2[0] += 128

print("Hashinput 1 : ", hashinput1, len(hashinput1), "bits\n")
print("Hashinput 2 : ", hashinput2, len(hashinput2), "bits\n")

print("\n=============================================")
print("Generating 1024 bytes (8192 bits) of all zeros")
print("================================================\n")

hash_obj1 = SHA3_512.new()
hash_obj1.update(hashinput1)
hashoutput1 = hash_obj1.hexdigest()
print("Hashoutput 1 : ", hashoutput1, "\n")

hash_obj2 = SHA3_512.new()
hash_obj2.update(hashinput2)
hashoutput2 = hash_obj2.hexdigest()
print("Hashoutput 2 : ", hashoutput2, "\n")

print("\n=============================================")
print("Printing out hamming distance between two output")
print("================================================\n")

print(hamming_distance(hashoutput1, hashoutput2))

#https://github.com/Legrandin/pycryptodome/blob/master/Doc/src/hash/sha3_512.rst
