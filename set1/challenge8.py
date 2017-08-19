#!/usr/bin/python

## Importing crypty python library
import sys
sys.path.insert(0,"..")

"""
Main Code
"""

import crypty
from crypty.ciphers import ecb as aes_ecb

def get_ciphertexts():
  fp = open("8.txt", "r")
  return [line.strip() for line in fp.readlines()]

def solve():
  ciphertexts = get_ciphertexts()
  for idx,ciphertext in enumerate(ciphertexts):
    blocks = crypty.get_blocks(ciphertext, block_size=16)
    if len(blocks)>len(set(blocks)):
      print "[+] Found ECB Encrypted line : %d "%(idx)

if __name__=='__main__':
  solve()