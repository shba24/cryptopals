#!/usr/bin/python

import crypty
from Crypto.Cipher import AES

def encrypt(plaintext, key):
  """
  Encrypts plaintext with key using AES-128-ECB
  Provide Padded plaintext to encrypt, aligned with blocksize = 16
  :param plaintext: hex string
  :param key: hex string
  :return: hex string
  """
  encrypter = AES.new(crypty.h2a(key), AES.MODE_ECB)
  return crypty.a2h(encrypter.encrypt(crypty.h2a(plaintext)))

def decrypt(ciphertext, key):
  """
  Decrypts ciphertext with key using AES-128-ECB
  Doesn't remove padding from decrypted string
  :param ciphertext: hex string
  :param key: hex string
  :return: hex string
  """
  decrypter = AES.new(crypty.h2a(key), AES.MODE_ECB)
  plaintext = crypty.a2h(decrypter.decrypt(crypty.h2a(ciphertext)))
  return plaintext