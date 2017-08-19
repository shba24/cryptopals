#!/usr/bin/python

## Importing crypty python library
import sys
sys.path.insert(0,"..")

"""
Main Code
"""

import crypty
from random import randint
from crypty.ciphers import cbc as aes_cbc
from crypty.ciphers import ecb as aes_ecb

def encryption_oracle(plaintext):
  key = crypty.generate_key()
  prefix = crypty.generate_key(key_size=randint(5,10))
  suffix = crypty.generate_key(key_size=randint(5,10))
  plaintext = prefix + plaintext + suffix
  if randint(0,2)==0:
    print "[*] Encrypting with CBC."
    iv = crypty.generate_key()
    return aes_cbc.infra.encrypt_manual(plaintext, key, iv)
  else:
    print "[*] Encrypting with ECB."
    plaintext = crypty.pad_pkcs_7(plaintext)
    return aes_ecb.infra.encrypt(plaintext, key)

def solve():
  plaintext = crypty.a2h("A"*43)
  ciphertext = encryption_oracle(plaintext)
  ciphertext_blks = crypty.get_blocks(ciphertext)
  if ciphertext_blks[1] == ciphertext_blks[2]:
    print "[+] Detected ECB Encryption."
  else:
    print "[+] Detected CBC Encryption."
  return

if __name__=='__main__':
  solve()