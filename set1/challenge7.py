#!/usr/bin/python


## Importing crypty python library
import sys
sys.path.insert(0,"..")

"""
Main Code
"""

import crypty
from crypty.ciphers import ecb as aes_ecb


def get_ciphertext():
  fp = open("7.txt","r")
  result = ""
  for line in fp.readlines():
    result+=line.strip()
  return result

def solve():
  ciphertext = crypty.convert_b64_to_hex(get_ciphertext())
  key = crypty.a2h("YELLOW SUBMARINE")
  plaintext = crypty.h2a(aes_ecb.infra.decrypt(ciphertext, key))
  print plaintext

if __name__=='__main__':
  solve()