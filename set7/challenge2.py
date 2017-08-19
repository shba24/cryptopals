"""
Main Code.
"""
import os
import sys
import itertools
from crypty import a2h, h2a, generate_key, pad_pkcs_7, unpad_pkcs_7,xor_ascii_strings
from crypty.ciphers import cbc as aes_cbc

def hash(message):
    message = pad_pkcs_7(a2h(message))
    return aes_cbc.infra.encrypt_manual(message, a2h("YELLOW SUBMARINE"), "00"*16)

def findCollision(message, prefix):
    extra = (7 - len(prefix))%16
    if extra == 0:
        extra = 16
    for extraPadding in itertools.product([chr(c) for c in xrange(0x30, 0x7b)], repeat=extra):
        new_prefix = prefix + "".join(list(extraPadding))
        print new_prefix
        prefixHash = h2a(hash(new_prefix))
        mid_part = h2a(xor_ascii_strings(prefixHash, message[:16]))
        if not all(ord(c)>=32 and ord(c)<127 for c in mid_part):
            continue
        mal_message = h2a(pad_pkcs_7(a2h(new_prefix)) + h2a(xor_ascii_strings(prefixHash, message[:16])) + message[16:]
        return mal_message
    return ""

def solver():
    message = "alert('MZA who was that?');\n"
    h = hash(message)

    prefix = b"alert('Ayo, the Wu is back!'); //"
    collision = findCollision(message, prefix)
    print "[+] Found one."
    print a2h(collision)
    return

if __name__=='__main__':
    solver()