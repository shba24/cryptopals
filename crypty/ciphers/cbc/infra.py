#!/usr/bin/python

import crypty
from crypty.ciphers import ecb as ecb_cipher

def encrypt_manual(hex_string, key, iv):
  """
  Manually AES-128-CBC Encrypts the input hex string using key, iv and AES-128-ECB
  :param hex_string: Hex string
  :param key: Hex string
  :param iv: Hex string
  :return: hex string
  """
  assert len(iv) == len(key)
  blocks = crypty.get_blocks(hex_string, block_size=16)
  ciphertext = ""
  for block in blocks:
    if len(crypty.h2a(block)) % 16 is not 0:
      block = crypty.pad_pkcs_7(block, block_size=16)
    xor_block = crypty.xor_hex_strings(block, iv)
    iv = ecb_cipher.infra.encrypt(xor_block, key)
    ciphertext+=iv

  return ciphertext

def decrypt_manual(hex_string, key, iv, raiser=True):
  """
  Manually AES-128-CBC decrypts the input hex string using key, iv and AES-128-ECB
  :param hex_string: Hex string
  :param key: Hex string
  :param iv: Hex string
  :return: hex string
  """
  assert len(iv) == len(key)
  blocks = crypty.get_blocks(hex_string, block_size=16)
  plaintext = ""
  for block in blocks:
    xor_block = ecb_cipher.infra.decrypt(block, key)
    plaintext += crypty.xor_hex_strings(xor_block, iv)
    iv = block
  if crypty.is_pcks7_padded(plaintext):
    plaintext = crypty.unpad_pkcs_7(plaintext)
  elif raiser:
    raise Exception("Wrongly padded hex string")
  return plaintext


