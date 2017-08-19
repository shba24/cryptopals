#!/usr/bin/python

import gmpy2
from crypty import a2h, h2a
from gmpy2 import mpz,powmod, t_mod, invert, iroot, mpz_random
from Crypto.Util.number import getPrime

def generatePrime(bits):
  return mpz(getPrime(bits))

### phi and e must be co-primes
def rsa_init(e=None, key_size=128):
  if e is None:
      e = generatePrime(key_size)
  p = generatePrime(key_size)
  while (p%e)==1 :
    p = generatePrime(key_size)
  q = generatePrime(key_size)
  while (q%e)==1:
    q = generatePrime(key_size)
  N = p*q
  phi = (p-1)*(q-1)
  d = invert(e,phi)
  return (e, d, N)

def encrypt(plaintext, e, N):
  """
  Encrypts the plaintext with public key e using RSA encryption.
  :param plaintext: ascii string
  :param e: public key
  :param N: public modulo
  :return: RSA encrypted string.
  """
  if type(plaintext) == str:
    plaintext = mpz(a2h(plaintext), base=16)
  return pow(plaintext, e, N)

def decrypt(cipher, d, N):
  """
  Decrypts the ciphertext with private key using RSA decryption
  :param ciphertext: integer
  :param d: private key
  :param N: public modulo
  :return: RSA decrypted string.
  """
  if type(cipher) == str:
    cipher = mpz(a2h(cipher), base=16)
  return pow(cipher, d, N)