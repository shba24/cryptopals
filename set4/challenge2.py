#!/usr/bin/python

"""
Main Code
"""

import crypty
from crypty.ciphers import ctr as aes_ctr

key = crypty.generate_key()
nounce = 0

def encrypter(userdata):
  userdata = userdata.replace(";","%3B").replace("=","%3D")
  prefix = "comment1=cooking%20MCs;userdata="
  suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
  plaintext = prefix + userdata + suffix
  ciphertext = aes_ctr.infra.encrypt(crypty.a2h(plaintext), key, nounce)
  return ciphertext

def decrypter(ciphertext):
  plaintext = aes_ctr.infra.decrypt(ciphertext, key, nounce)
  return plaintext.decode("hex").find(";admin=true;")!=-1

def solve():
  ciphertext = encrypter('A'*16)
  blocks = crypty.get_blocks(ciphertext)
  old_cipher_block = blocks[2]
  new_cipher_block = crypty.xor_hex_strings(crypty.xor_hex_strings(old_cipher_block, crypty.a2h('A'*16)), crypty.a2h(";admin=true;XXXX"))
  blocks[2] = new_cipher_block
  if decrypter("".join(blocks)):
    print "New Ciphertext : %s"%("".join(blocks))

if __name__=='__main__':
  solve()