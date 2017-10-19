#!/usr/bin/python

"""
Main Code
"""

import crypty
from crypty.ciphers import ctr as aes_ctr

def solve():
  ciphertext = crypty.convert_b64_to_hex("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
  KEY = crypty.a2h("YELLOW SUBMARINE")
  nounce = 0
  print aes_ctr.infra.decrypt(ciphertext, KEY, nounce).decode("hex")

if __name__=='__main__':
  solve()