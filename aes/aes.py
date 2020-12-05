"""
CS547 Homework AES-256 Encryption : 20193577 Hyewon Jeong (2019.09.24.)

===============
Homework Report
===============

AES-256 implementation in pure python, and some of the functions are adopted
from Bo Zhu's implementation [1]. PKCS#7 padding, CBC mode, PKBDF2, HMAC, byte array 
and string support were added using [2]. This algorithm works as follows:

1. Salt <- Random
system's secure random number generator extracts 16 random bytes of salt
- This ensures the same message is mapped to different ciphertexts.

2. Stretching and Expanding Salt from 1 with PKBDF2-HMAC(SHA256)
stretch and expand in order to generate the AES key(key_aes), HMAC key(key_hmac) 
and initialization vector for CBC(IV). In this process, HMAC ensures the integrity of both
entire ciphertext and PKBDF2 salt; encrypt-then-mac prevents attacks like Padding Oracle. 

3. Encryption in CBC mode (E_key_aes(message, iv))
Message is encrypted in CBC mode and PKCS#7 padding with AES-128 using AES key 
and IV from 2. 

4. HMAC-SHA generation (HMAC(salt + E_key_aes(message, iv)))
HMAC-SHA256 is generated from the concatenation of the salt from 1 and
the ciphertext from 3.

5. Final ciphertext : HMAC + salt + ciphertext

After adopting algorithms above, I added several handy functions:
generate_bytearray generates bytearray of 0's for key and plaintext generation. 
generate_binpad pad binary strings in order to ensure everything is in the same length. 
When they are bytes, as in a string, they should be 8 0's long '0b00000000' = len 10
Then this binary array key is put into AES class to generate encrypted ciphers.
The result we get at the end shows that when encrypted with maximum distance between two plaintext,
the minimal hamming distance come out as a result of AES. 

References
1. https://github.com/bozhu/AES-Python (Original Implementation by Bo Zhu (http://about.bozhu.me))
2. https://github.com/boppreh/aes (Original Implementation by Lucas Boppre (http://boppreh.com))
"""

import os
import copy
from scipy.spatial.distance import hamming

from hmac import new as new_hmac
from hmac import compare_digest
from hashlib import pbkdf2_hmac

# Declare Variables salt, inverse salt
s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

AES_KEY_SIZE = 32
HMAC_KEY_SIZE = 16
IV_SIZE = 16

SALT_SIZE = 16
HMAC_SIZE = 32


#Defining Some handy functions for bytearray generation, padding, and hamming disatance calculation
"""
This function "generate_bytearray" Receives byte no. and generates bytearray of 0's to make key and plaintext
"""
def generate_bytearray(b: int) -> bytearray:
    bytarr = bytearray(b)
    for i in range(b):
        bytarr[i] = 0
    return bytarr

"""
This function "generate_padding" Pads binary strings in order to ensure everything is in the same length (len = 10).  
"""
def generate_binpad(s):
    if len(s) < 10:
        return s[:2] + "0" * (10 - len(s)) + s[2:]
    else:
        return s

"""
This function "Calculating HWeights" calculates hamming disatance between two binary input. 
It first converts interger to binary, pad them using generate binpad function above.   
"""
# loop through lists of integers, convert to binary, pad them properly with 0's
def Calculating_HWeights(x, y):
    length = len(x)
    dist = 0

    for i in range(length):
        x_bin = generate_binpad(bin(x[i]))
        y_bin = generate_binpad(bin(y[i]))

        for idx, val in enumerate(x_bin[2:]):
            if val != y_bin[idx+2]:
                dist += 1
            else:
                continue
    
    return dist

"""
These functions and class are adopted from Ref [1]
"""
def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]

def inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]

def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]

# learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)

def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])

def inv_mix_columns(s):
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)

def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i : i + 4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))

def xor_bytes(a, b):
    """ Returns a new byte array with the elements xor'ed. """
    return bytes(i ^ j for i, j in zip(a, b))

def pad(plaintext):
    """
    Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
    Note that if the plaintext size is a multiple of 16,
    a whole block will be added.
    """
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

def unpad(plaintext):
    """
    Removes a PKCS#7 padding, returning the unpadded text and ensuring the
    padding was correct.
    """
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message


class AES(object):
    """
    Class for AES-128 encryption with CBC mode and PKCS#7.
    This is a raw implementation of AES, without key stretching or IV
    management. Unless you need that, please use `encrypt` and `decrypt`.
    """
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}

    def __init__(self, master_key):
        """
        Initializes the object with a given key.
        """
        assert len(master_key) in AES.rounds_by_key_size
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key):
        """
        Expands and returns a list of key matrices for the given master_key.
        """
        # Initialize round keys with raw key material.
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4

        # Each iteration has exactly as many columns as the key material.
        columns_per_iteration = len(key_columns)
        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            # Copy previous word.
            word = list(key_columns[-1])

            # Perform schedule_core once every "row".
            if len(key_columns) % iteration_size == 0:
                # Circular shift.
                word.append(word.pop(0))
                # Map to S-BOX.
                word = [s_box[b] for b in word]
                # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                # Run word through S-box in the fourth iteration when using a
                # 256-bit key.
                word = [s_box[b] for b in word]

            # XOR with equivalent word from previous iteration.
            word = xor_bytes(word, key_columns[-iteration_size])
            key_columns.append(word)

        # Group key words in 4x4 byte matrices.
        return [key_columns[4 * i : 4 * (i + 1)] for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext, step_bl):
        assert len(plaintext) == 16
        P_state = bytes2matrix(plaintext)
        add_round_key(P_state, self._key_matrices[0])

        print(f"{P_state}\nStart changing stuff.")
        # END EDIT
        for d in range(1, self.n_rounds):
            # START EDIT
            bl=[]
            for p in P_state:
                for s in p:
                    bl.append(s)
            step_bl.append(bl)
            add_round_key(P_state, self._key_matrices[d])
            sub_bytes(P_state)
            shift_rows(P_state)
            mix_columns(P_state)

        shift_rows(P_state)
        sub_bytes(P_state)
        add_round_key(P_state, self._key_matrices[-1])

        return matrix2bytes(P_state)

    def decrypt_block(self, ciphertext):
        """
        Decrypts a single block of 16 byte long ciphertext.
        """
        assert len(ciphertext) == 16

        cipher_state = bytes2matrix(ciphertext)

        add_round_key(cipher_state, self._key_matrices[-1])
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)

        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(cipher_state, self._key_matrices[i])
            inv_mix_columns(cipher_state)
            inv_shift_rows(cipher_state)
            inv_sub_bytes(cipher_state)

        add_round_key(cipher_state, self._key_matrices[0])

        return matrix2bytes(cipher_state)

    def encrypt_cbc(self, plaintext, iv):
        """
        Encrypts `plaintext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        plaintext = pad(plaintext)

        blocks = []
        previous = iv
        # Splits in 16-byte parts.
        for i in range(0, len(plaintext), 16):
            plaintext_block = plaintext[i : i + 16]
            # CBC mode encrypt: encrypt(plaintext_block XOR previous)
            block = self.encrypt_block(xor_bytes(plaintext_block, previous), P_state)
            blocks.append(block)
            previous = block

        return b"".join(blocks)

    def decrypt_cbc(self, ciphertext, iv):
        """
        Decrypts `plaintext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 16

        blocks = []
        previous = iv
        # Splits in 16-byte parts.
        for i in range(0, len(ciphertext), 16):
            ciphertext_block = ciphertext[i : i + 16]
            # CBC mode decrypt: previous XOR decrypt(ciphertext)
            blocks.append(xor_bytes(previous, self.decrypt_block(ciphertext_block)))
            previous = ciphertext_block

        return unpad(b"".join(blocks))

def get_key_iv(password, salt, workload=100000):
    """
    Stretches the password and extracts an AES key, an HMAC key and an AES
    initialization vector.
    """
    stretched = pbkdf2_hmac(
        "sha256", password, salt, workload, AES_KEY_SIZE + IV_SIZE + HMAC_KEY_SIZE
    )
    aes_key, rest = stretched[:AES_KEY_SIZE], stretched[AES_KEY_SIZE:]
    hmac_key, rest = stretched[:HMAC_KEY_SIZE], stretched[HMAC_KEY_SIZE:]
    iv = stretched[:IV_SIZE]
    return aes_key, hmac_key, iv

def encrypt(key, plaintext, workload=100000):
    """
    Encrypts `plaintext` with `key` using AES-128, an HMAC to verify integrity,
    and PBKDF2 to stretch the given key.
    The exact algorithm is specified in the module docstring.
    """
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    salt = os.urandom(SALT_SIZE)
    key, hmac_key, iv = get_key_iv(key, salt, workload)
    ciphertext = AES(key).encrypt_cbc(plaintext, iv)
    hmac = new_hmac(hmac_key, salt + ciphertext, "sha256").digest()
    assert len(hmac) == HMAC_SIZE

    return hmac + salt + ciphertext

def decrypt(key, ciphertext, workload=100000):
    """
    Decrypts `plaintext` with `key` using AES-128, an HMAC to verify integrity,
    and PBKDF2 to stretch the given key.
    The exact algorithm is specified in the module docstring.
    """

    assert len(ciphertext) % 16 == 0, "Ciphertext must be made of full 16-byte blocks."

    assert (
        len(ciphertext) >= 32
    )
    """
    Ciphertext must be at least 32 bytes long (16 byte salt + 16 byte block). To
    encrypt or decrypt single blocks use `AES(key).decrypt_block(ciphertext)`.
    """

    if isinstance(key, str):
        key = key.encode("utf-8")

    hmac, ciphertext = ciphertext[:HMAC_SIZE], ciphertext[HMAC_SIZE:]
    salt, ciphertext = ciphertext[:SALT_SIZE], ciphertext[SALT_SIZE:]
    key, hmac_key, iv = get_key_iv(key, salt, workload)

    expected_hmac = new_hmac(hmac_key, salt + ciphertext, "sha256").digest()
    assert compare_digest(hmac, expected_hmac), "Ciphertext corrupted or tampered."

    return AES(key).decrypt_cbc(ciphertext, iv)


if __name__ == "__main__":
    pstate=[]
    block_ciphers = []

    # 0. Generating bytearray key and plain text using "generate_bytearray" function
    key = generate_bytearray(32)
    text_plain = [generate_bytearray(16), generate_bytearray(16)]

    # 1. Input Containig 1-bit change of plaintext as inputs for encryption. (Assignment Instruction 1)
    text_plain[1][-1] = text_plain[1][-1] ^ 1
    
    
    # 1-1. Printing out generated bytearray on screen for reporting
    for idx, value in enumerate(text_plain):
        print(f"Generated Plain Text are: {idx+1}: {value}")
    print(f"\nGenerated key is: {key}\n")


    # 1-2. Put key in class AES
    aes = AES(key)

    # 2. Encrypting Plaintext (print out plaintext, cipher)
    print("\n=====================================================================")
    print("Encrypting Plaintext.... Printing out plaintext and block cipher")
    print("=====================================================================\n")

    for idx, value in enumerate(text_plain):
        print(f"\nEncrypted Plaintext: {idx+1}\n")
        ciphert = b""
        for l in range(len(value) // 16):
            print(f"Encrypted block cipher: {l+1}/{len(value) // 16}")
            ciphert += aes.encrypt_block(value[l*16 : (l + 1) * 16], pstate)
        print(f"Ciphertext : {ciphert}")
        block_ciphers.append(ciphert)

    step = len(pstate) // 2

    # 3. Calculate hamming weights, Comparing 
    print("\n=====================================================================")
    print("Comparing Calculated Hamming Weights Between Bytearray Plaintexts")
    print("=====================================================================\n")

    """
    Printing out hamming weights on each rounds (Assignment Instruction 2).
    """
    print("=====================================================================================================================================")
    for i in range(step):
        print(f"Hamming distance of round #{step}: {Calculating_HWeights(pstate[i], pstate[i+step])}\n")
    print("=====================================================================================================================================")

    print("\n=====================================================================")
    print("Decrypting Ciphertext.... Printing out decrypted ciphertext")
    print("=====================================================================\n")
    for idx, j_ in enumerate(block_ciphers):
        text = b""
        for i in range(len(j_) // 16):
            text += aes.decrypt_block(j_[i * 16 : (i + 1) * 16])
        #CONDITION
        print(f"Decrypted Cipher Text: {text}")
        print(f"Decrypted Cipher == Plain Text: {text == text_plain[idx]}\n")
    
    print("\n=====================================================================")
    print(f"Cipher Text 1 is : {block_ciphers[0]}")
    print(f"Cipher Text 2: {block_ciphers[1]}")
    print("=====================================================================================================================================")
    print(f"Final Calculated Hamming distance between cipher texts 1 and 2: {Calculating_HWeights(block_ciphers[0], block_ciphers[1])}")
    print("=====================================================================================================================================")
