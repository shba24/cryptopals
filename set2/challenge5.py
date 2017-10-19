#!/usr/bin/python

"""
Main Code
"""

import crypty
from crypty.ciphers import ecb as ecb_cipher

key = None

def sanitize(s):
  return s.replace("&","").replace("=","")

def encode_profile(profile):
  result = ""
  for kv in profile:
    sanitized_kv = [sanitize(x) for x in kv]
    if len(result):
      result+='&'
    result += sanitized_kv[0]+'='+sanitized_kv[1]
  return result

def profile_for(email):
  profile = [
    ['email', email],
    ['uid', '10'],
    ['role', 'user']
  ]
  return encode_profile(profile)

def encrypt_profile(profile):
  global key
  if key is None:
    key = crypty.generate_key()
  ciphertext = ecb_cipher.infra.encrypt(crypty.pad_pkcs_7(crypty.a2h(profile)), key)
  return (key,ciphertext)

def decrypt_profile(ciphertext, key):
  plaintext = ecb_cipher.infra.decrypt(ciphertext, key)
  plaintext = crypty.h2a(crypty.unpad_pkcs_7(plaintext))
  pairs = plaintext.split("&")
  profile = []
  for p in pairs:
    profile.append([ x.encode("ascii") for x in p.split("=") ])
  return profile

def solve():
  email_1 = "foo@bar.coadmin"+'\x0b'*11
  key, cipher_1 = encrypt_profile(profile_for(email_1))
  email_2 = "foo@bar.commm"
  key, cipher_2 = encrypt_profile(profile_for(email_2))
  ciphertext = cipher_2[:64]+cipher_1[32:64]
  print decrypt_profile(ciphertext, key)

if __name__=='__main__':
  solve()