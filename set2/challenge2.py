#!/usr/bin/python

"""
Main Code
"""

import crypty
from crypty.ciphers import cbc as aes_cbc

def get_ciphertexts():
  fp = open("10.txt", "r")
  return "".join([line.strip() for line in fp.readlines()])

def solve():
  ciphertext = crypty.convert_b64_to_hex(get_ciphertexts())
  key = crypty.a2h("YELLOW SUBMARINE")
  iv = crypty.a2h("\x00"*16)
  print crypty.h2a(aes_cbc.infra.decrypt_manual(ciphertext, key, iv))

if __name__=='__main__':
  solve()