#!/usr/bin/python

import crypty

char_freqs = {
    'a': 0.0651738,
    'b': 0.0124248,
    'c': 0.0217339,
    'd': 0.0349835,
    'e': 0.1041442,
    'f': 0.0197881,
    'g': 0.0158610,
    'h': 0.0492888,
    'i': 0.0558094,
    'j': 0.0009033,
    'k': 0.0050529,
    'l': 0.0331490,
    'm': 0.0202124,
    'n': 0.0564513,
    'o': 0.0596302,
    'p': 0.0137645,
    'q': 0.0008606,
    'r': 0.0497563,
    's': 0.0515760,
    't': 0.0729357,
    'u': 0.0225134,
    'v': 0.0082903,
    'w': 0.0171272,
    'x': 0.0013692,
    'y': 0.0145984,
    'z': 0.0007836,
    ' ': 0.1918182
}

def hamming_distance_normalised(str1, str2):
  """
  Calculates Hamming distance between two strings and returns the probability
  :param str1: hex string
  :param str2: hex string
  :return: 0<=p<=8
  """
  return crypty.hamming_distance(str1, str2)/float(len(crypty.h2a(str1)))

def keysize_estimator(ciphertext, start=1, end=32):
  """
  Estimtes the key size using haamming distance/edit distance
  :param ciphertext: hex string
  :param start: starting key size to brute force
  :param end: ending key size to brute force
  :return: returns top 3 probable keys sizes in tuple form of (score, key size)
  """
  hamming_scores = []
  for sz in xrange(start,end+1):
    count, total = 0 , 0.0
    for i in xrange(0, len(ciphertext)-(2*sz), 2*sz):
      for j in xrange(i+(2*sz), len(ciphertext)-(2*sz), 2*sz):
        total += hamming_distance_normalised(ciphertext[i:i+2*sz],ciphertext[j:j+2*sz])
        count += 1
    total = total/float(count)
    hamming_scores.append((total, sz))
  return sorted(hamming_scores, key=lambda tup: tup[0])[:3]

def freq_calculator(plaintext):
  """
  Shows the probability of a plaintext being a ascii plaintext
  :param plaintext: string
  :return: probability 0<=p<=1
  """
  return sum(char_freqs[c.lower()] for c in plaintext if c.lower() in char_freqs.keys())/len(plaintext)

def check_key(hex_cipher, key, score_calculator):
  """
  Checks if a particular key for xor cipher is correct or not.
  :param hex_cipher: hex string
  :param key: hex string
  :param score_type: either ascii or raw
  :return: tuple of probability score and key
  """
  plaintext = crypty.xor_rep_hex_strings(hex_cipher, key)
  score = score_calculator(crypty.h2a(plaintext))
  return (score, key, crypty.h2a(plaintext))

def get_cipher_indexes(hex_cipher, idx, key_len):
  """
  Returns a string of all char at index idx in all blocks
  :param hex_cipher: hex string
  :param idx: int
  :return: hex string
  """
  raw_cipher = crypty.h2a(hex_cipher)
  result = ""
  for start in xrange(0,len(raw_cipher),key_len):
    block = raw_cipher[start:start+key_len]
    if idx >= len(block):
      break
    result += block[idx]
  return crypty.a2h(result)

def brute_force(hex_cipher,key_len, score_calculator=freq_calculator):
  """
  Brute Forces the key size and key from length start to end
  :param hex_cipher: hex string
  :param key_len: user supplied key length
  :param score_calculator: user provided function to calculate the probability of keys default=freq_calculator
  :param start: starting key size default=1
  :param end: ending key size default=32
  :return: hex string of key
  """
  if len(hex_cipher) is 0:
    raise Exception("Empty Cipher text")
  if key_len is not 1:
    key = ""
    for i in xrange(0,key_len):
      ciphertext = get_cipher_indexes(hex_cipher,i,key_len)
      key+=brute_force(ciphertext, key_len=1)
    final_ans = key
  else:
    key_scores = []
    for key_int in xrange(0,1<<8):
      key_scores.append(check_key(hex_cipher, crypty.i2h(key_int), score_calculator))
    key_scores = sorted(key_scores, key=lambda tup: tup[0],reverse=True)[:3]
    final_ans = key_scores[0][1]

  return final_ans
