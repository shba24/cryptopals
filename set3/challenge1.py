#!/usr/bin/python

"""
Main Code
"""

import crypty
from random import randint
from crypty.ciphers import cbc as aes_cbc

plaintexts = """MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93""".split("\n")

key = crypty.generate_key()

def encrypter():
  plaintext = crypty.convert_b64_to_hex(plaintexts[randint(0,len(plaintexts))])
  #print plaintext.decode("hex")
  iv = crypty.generate_key()
  ciphertext = aes_cbc.infra.encrypt_manual(plaintext, key, iv)
  return (iv, ciphertext)

def padding_oracle(ciphertext, iv):
  try:
    aes_cbc.infra.decrypt_manual(ciphertext, key, iv)
    return True
  except:
    return False

def decipher_block(iv, block):
  predict = ['\x00']*16
  for i in xrange(15, -1, -1):
    for c in xrange(0,256):
      predict[i] = chr(c)
      padding = (chr(16-i)*(16-i)).rjust(16,'\x00')
      new_iv = crypty.xor_hex_strings(crypty.xor_ascii_strings("".join(predict), crypty.h2a(iv)), crypty.a2h(padding))
      if padding_oracle(block, new_iv):
        if i==15:
          # Recheck for the correctness of found byte, whether its a genioun padding at the end or just random thing.
          flag = False
          for ch in xrange(0,256):
            new_iv = crypty.xor_hex_strings(crypty.xor_ascii_strings("".join(['\x00']*14)+chr(ch)+chr(c), crypty.h2a(iv)),crypty.a2h("\x00"*14+"\x02\x02"))
            if padding_oracle(block, new_iv):
              flag = True
              break
          if flag:
            break
        else:
          break
  return "".join(predict).encode("hex")

def solve():
  iv, ciphertext = encrypter()
  blocks = crypty.get_blocks(ciphertext)
  plaintext = ""
  for i in xrange(len(blocks)):
    x = decipher_block(iv, blocks[i])
    iv = blocks[i]
    plaintext += x
  print plaintext.decode("hex")

if __name__=='__main__':
  solve()