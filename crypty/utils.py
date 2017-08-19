#!/usr/bin/python

import binascii
from Crypto.Random import random

def hamming_distance(str1, str2):
  """
  Calculates Hamming distance between two strings
  :param str1: hex string
  :param str2: hex string
  :return: int
  """
  assert len(str1) == len(str2)
  result = hex_to_bin(xor_hex_strings(str1, str2))
  return result.count('1')

def h2a(str):
  """
  Convert hex to ascii
  :param str: hex string
  :return: integer
  """
  return binascii.unhexlify(str)


def a2h(str):
  """
  Convert ascii to hex
  :param str: ascii string
  :return: hex string
  """
  return binascii.hexlify(str)


def i2h(i):
  """
  Converts integers into a hex encoded strings with leading zeroes
  :param i: integer
  :return: hex string
  """
  ans = format(i,'x') if len(format(i,'x'))%2 is 0 else "0"+format(i,'x')
  return ans


def xor_ascii_strings(str1, str2):
  """

  Xor two input ascii string and returns resultant ascii string

  :param str1: ascii String
  :param str2: ascii String
  :return: hex String
  """
  if len(str1) > len(str2):
    return a2h("".join([chr(ord(a) ^ ord(b)) for a, b in zip(str1[:len(str2)], str2)]))
  else:
    return a2h("".join(chr(ord(a) ^ ord(b)) for a, b in zip(str1, str2[:len(str1)])))

def xor_hex_strings(str1, str2):
  """

  Xor two input hex string and returns resultant hex string

  :param str1: Hex String
  :param str2: Hex String
  :return: Hex String
  """
  return xor_ascii_strings(h2a(str1), h2a(str2))

def xor_rep_hex_strings(str1, str2):
  """
  Repeated XOR str1 and str2
  :param str1: Hex String
  :param str2: Hex String
  :return: Hex String
  """

  ## Check if length of str1 is greater than str2
  ## and if it's not than swap str1 and str2
  if len(str1) < len(str2):
    str1, str2 = str2, str1
  ans = ""
  for start in xrange(0,len(str1),len(str2)):
    ans = ans + xor_hex_strings(str1[start:start+len(str2)], str2)
  return ans

def convert_hex_to_b64(hex_string):
  """
  Convert input hex string into base64 encoded hex string

  :param hex_string: Hex String
  :return: Hex String
  """
  return binascii.b2a_base64(h2a(hex_string))

def convert_b64_to_ascii(b64_string):
  """
  Convert input base64 encoded string to ascii string
  :param b64_string: base64 encoded string
  :return: ascii string
  """
  return binascii.a2b_base64(b64_string)

def convert_b64_to_hex(b64_string):
  """
  Convert input base64 string to hex string
  :param b64_string: base64 encode string
  :return: hex string
  """
  return a2h(convert_b64_to_ascii(b64_string))

def ascii_to_bin(str):
  """
  Converts ascii string into binary representation
  :param str: ascii string
  :return: binary string
  """
  return "".join([ bin(ord(c)).lstrip('0b').rjust(8,'0') for c in list(str)])

def hex_to_bin(hex_string):
  """
  Converts hex string into binary representation
  :param hex_string: hex string
  :return: binary representation
  """
  return ascii_to_bin(h2a(hex_string))

def get_blocks(hex_string, block_size=16):
  """
  Splits hex_string into blocks of size block_size or whatever is available
  :param hex_string: hex string
  :param block_size: int
  :return: list of all the blocks
  """
  raw_string = h2a(hex_string)
  return [a2h(raw_string[i:i+block_size]) for i in xrange(0, len(raw_string), block_size)]

def is_pcks7_padded(hex_string):
  """
  Checks if the hex string is pkcs#7 padded or not
  :param hex_string: hex string
  :return: Bool
  """
  raw_string = h2a(hex_string)
  pad_len = ord(raw_string[-1])
  if raw_string[-pad_len:] == raw_string[-1]*pad_len:
    return True
  else:
    return False

def pad_pkcs_7(hex_string, block_size=16):
  """
  Pads given hex string with PKCS#7 padding
  :param hex_string: Hex String
  :param block_size: Block Size
  :return: hex string
  """
  pad_sz = block_size - len(h2a(hex_string))%block_size
  return hex_string + a2h(chr(pad_sz)*pad_sz)

def unpad_pkcs_7(hex_string):
  """
  Removes pkcs#7 padding from the hex string
  :param hex_string: hex string
  :return: hex string
  """
  raw_string = h2a(hex_string)
  pad_len = ord(raw_string[-1])
  if is_pcks7_padded(hex_string):
    return a2h(raw_string[:-pad_len])
  else:
    raise Exception("Wrongly padded hex string")

def generate_key(key_size=16):
  """
  Generates a key of length key_size using sys pseudo random
  :param key_size: int
  :return: hex string
  """
  import os
  return a2h(os.urandom(key_size))

def get_sha1_regs(hash):
  """
  Returns a,b,c,d,e registers used in the SHA1 hash
  :param hash: hex string
  :return: list of regs
  """
  import struct
  assert len(hash) == 40
  return list(struct.unpack('>5I', hash.decode("hex")))

def get_salt(sz=64):
  """
  Returns the random integer of size sz.
  :param size: integer
  :return: random integer of size sz
  """
  return random.getrandbits(sz)

def egcd(a, b):
  if b == 0:
    return (1, 0)
  else:
    q = a // b
    r = a % b
    (s, t) = egcd(b, r)
    return (t, s - q * t)


# Returns a^-1 mod N
def invmod(a, N):
  # ax + by = 1:
  # ax - 1 = by
  # ax - 1 = 0 mod b
  # ax = 1 mod b
  # x is the inverse of a mod b
  (x, y) = egcd(a, N)
  return x % N