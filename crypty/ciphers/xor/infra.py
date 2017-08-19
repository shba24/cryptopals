#!/usr/bin/python

import crypty

def encrypt(plaintext, key):
  """
  Encrypts the plaintext with key using repeated XOR cipher.
  :param plaintext: hex string
  :param key: hex string
  :return: hex string
  """
  return crypty.xor_rep_hex_strings(plaintext, key)

def decrypt(ciphertext, key):
  """
  Decrypts the ciphertext with key using the repeated XOR cipher
  :param ciphertext: hex string
  :param key: hex string
  :return: hex string
  """
  return encrypt(ciphertext, key)