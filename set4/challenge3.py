#!/usr/bin/python

"""
Main Code
"""

import crypty
from crypty.ciphers import cbc as aes_cbc

key = crypty.generate_key()
iv = key

print "[+] Choosen Key : %s"%(key)

def encrypter(userdata):
  userdata = userdata.replace(";","%3B").replace("=","%3D")
  ciphertext = aes_cbc.infra.encrypt_manual(crypty.a2h(userdata), key, iv)
  return ciphertext

def decrypter(ciphertext):
  plaintext = aes_cbc.infra.decrypt_manual(ciphertext, key, iv, raiser=False)
  return plaintext

def solve():
  ciphertext = encrypter('A'*16*3)
  blocks = crypty.get_blocks(ciphertext)
  blocks = [blocks[0],'00'*16,blocks[0]]
  plaintext = decrypter("".join(blocks))
  blocks = crypty.get_blocks(plaintext)
  foundkey = crypty.xor_hex_strings(blocks[0], blocks[2])
  print "Key : %s"%(foundkey)

if __name__=='__main__':
  solve()