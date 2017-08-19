#!/usr/bin/python


## Importing crypty python library
import sys
sys.path.insert(0,"..")

"""
Main Code
"""

import crypty
from crypty.ciphers import xor as xor_cipher

def solve():
  plaintext = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
  key = "ICE"
  return xor_cipher.infra.encrypt(crypty.a2h(plaintext), crypty.a2h(key))

if __name__=='__main__':
  print solve()