#!/usr/bin/python

## Importing crypty python library
import sys
sys.path.insert(0,"..")

"""
Main Code
"""

from crypty.ciphers import xor as xor_cipher

def solve():
  cipher_text = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
  return xor_cipher.attacks.brute_force(cipher_text,key_len=1,score_type="ascii")

if __name__=='__main__':
  print solve()