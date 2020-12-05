"""
Trial of AES256
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from scipy.spatial.distance import hamming

import pdb

pt1 = b"Hello World"
pt2 = b"Hello Worle"
key = get_random_bytes(32)

#pdb.set_trace()
crypt = AES.new(key, AES.MODE_EAX)

ct1 = crypt.encrypt(pt1)
ct2 = crypt.encrypt(pt2)

print(ct1, ct2)
print(hamming(ct1, ct2))
print(hamming(ct1, ct2))
print(hamming(ct1, ct2))
