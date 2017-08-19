#!/usr/bin/python

import crypty
from crypty.ciphers import ecb as ecb_cipher
import struct

def encrypt(plaintext, key, nounce):
  """
  Encrypts plaintext using AES-128-CTR Block Cipher
  :param plaintext: Hex string
  :param key: Hex string
  :param nounce: int
  :return: Hex string
  """
  plaintext = crypty.h2a(plaintext)
  nounce_little_endian = struct.pack("<q",nounce)
  keystream = []
  for ctr in xrange(len(plaintext)/16 + 1):
    ctr_little_endian = struct.pack("<q",ctr)
    keystream.append(ecb_cipher.infra.encrypt(crypty.a2h(nounce_little_endian+ctr_little_endian), key))
  keystream = "".join(keystream)[:len(plaintext)*2]
  return crypty.xor_hex_strings(keystream, crypty.a2h(plaintext))

def decrypt(ciphertext, key, nounce):
  """
  Decrypts plaintext using AES-128-CTR Block Cipher
  :param plaintext: Hex string
  :param key: Hex string
  :param nounce: int
  :return: Hex string
  """
  return encrypt(ciphertext, key, nounce)