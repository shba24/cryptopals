"""
Main Code
"""

import os
import sys
import random
import crypty
from crypty import h2a, i2h, a2h
from Crypto.Hash import SHA
from crypty.ciphers import cbc as aes_cbc
from crypty.hash import hmac
from gmpy2 import mpz, mpz_random, random_state, t_mod, powmod

rstate = random_state()

A_knows = {}
B_knows = {}
E_knows = {}
gr = []
gk = []

def getSHA1(MSG):
  h = SHA.new()
  h.update(MSG)
  return h.hexdigest()

# For A
# g^q = 1 mod p
# q is a prime, just like p
# q | p-1  <-- This guarantees that an element g of order q will exist(In fact, there will be q-1 such elements.)
def step1():
  p = mpz(7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771)
  g = mpz(4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143)
  q = mpz(236234353446506858198510045061214171961)
  a = t_mod(mpz_random(rstate, p-2)+2, q)
  A = pow(g, a, p)
  A_knows['q'] = q
  A_knows['p'] = p
  A_knows['g'] = g
  A_knows['a'] = a
  A_knows['A'] = A
  return (p,g,A)

def findfactor(x, bitlength):
    factor = []
    for i in xrange(2, 2**bitlength):
        if t_mod(x, i) == 0:
            factor.append(i)
    return factor

# Pohlig Hellman algorithm for discrete logarithms
def PohligHellman(factors):
    p = E_knows['p']
    h = None
    for r in factors:
        if r in gr:
            continue
        h = powmod(mpz_random(rstate, p-1) + 1, (p-1)/r, p)
        if h!=1:
            gr.append(r)
            return (r, h)
    return (None, None)

# For E
def step1_1(p,g,A):
  E_knows['p'] = p
  j = mpz(30477252323177606811760882179058908038824640750610513771646768011063128035873508507547741559514324673960576895059570)
  factors = findfactor(j, 16)
  (r, h) = PohligHellman(factors)
  E_knows['g'] = g
  E_knows['A'] = A
  E_knows['h'] = h
  E_knows['r'] = r
  return (p,g,h)

# For B
def step2(p,g,A):
  q = mpz(236234353446506858198510045061214171961)
  B_knows['q'] = q
  B_knows['p'] = p
  B_knows['g'] = g
  B_knows['A'] = A
  b = t_mod(mpz_random(rstate, p-2)+2, q)
  B = pow(g, b, p)
  B_knows['b'] = b
  B_knows['B'] = B
  B_knows['k'] = getSHA1(format(pow(A,b,p),'x'))[0:32]
  return B

# For E
def step2_1(B):
  E_knows['B'] = B
  return B

# For A
def step3(B):
  p = A_knows['p']
  a = A_knows['a']
  A_knows['B'] = B
  k = getSHA1(format(pow(B,a,p),'x'))[0:32]
  A_knows['k'] = k
  return

# For B
def step4(msg):
  k = B_knows['k']
  B_knows['msg'] = msg
  return hmac(msg, k)

def step4_1(msg, hash):
  h = E_knows['h']
  r = E_knows['r']
  p = E_knows['p']
  for x in xrange(1, r):
      k = getSHA1(format(powmod(h, x, p),'x'))[0:32]
      if hmac(msg, k) == hash:
          print "[+] Found the private key. r = %d"%(r)
          print "[+] Key: %s"%(k)
          gk.append(k)
          return True
  print "[-] No keys Found."
  return False

def solver():
  while len(gr)!=4:
    p, g, A = step1()   ### Original
    p, g, E = step1_1(p, g, A)   ### MITM
    B = step2(p, g, E)  ### Original
    E = step2_1(B)               ### MITM
    msg = "YOU ARE SAFE"
    step3(E)  ### Original
    mac = step4(msg)
    if not step4_1(msg, mac):
        gr.pop()
  print gr
  print gk
  return

if __name__=='__main__':
    solver()
