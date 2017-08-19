import sys

sys.path.insert(0,"..")

"""
Main Code
"""

from Crypto.Hash import SHA
import crypty
import random
from crypty.ciphers import cbc as aes_cbc


A_knows = {}
B_knows = {}
E_knows = {}

gtype = 2

def getSHA1(MSG):
  h = SHA.new()
  h.update(MSG)
  return h.hexdigest()

# For A
def step1():
  p = 37
  g = 5
  a = random.randint(2,p)
  A = pow(g, a, p)
  A_knows['p'] = p
  A_knows['g'] = g
  A_knows['a'] = a
  A_knows['A'] = A
  return (p,g,A)

# For E
def step1_1(p,g,A):
  E_knows['p'] = p
  gs = [1, p, p - 1]
  E_knows['g'] = gs[gtype]
  if gtype==0:
    E_knows['A'] = 1
  elif gtype==1:
    E_knows['A'] = p
  elif gtype==2:
    E_knows['A'] = p - 1
  return (p,g,E_knows['A'])

# For B
def step2(p,g,A):
  B_knows['p'] = p
  B_knows['g'] = g
  B_knows['A'] = A
  b = random.randint(2,p)
  B = pow(g, b, p)
  B_knows['b'] = b
  B_knows['B'] = B
  B_knows['k'] = getSHA1(format(pow(A,b,p),'x'))[0:32]
  return B

# For E
def step2_1(B):
  if gtype==0:
    E_knows['B'] = 1
  elif gtype==1:
    E_knows['B'] = E_knows['p']
  elif gtype==2:
    E_knows['B'] = E_knows['p']-1
  return E_knows['B']

# For A
def step3(msg, B):
  p = A_knows['p']
  a = A_knows['a']
  A_knows['B'] = B
  k1 = getSHA1(format(pow(B,a,p),'x'))[0:32]
  A_knows['k1'] = k1
  A_knows['msg'] = msg
  iv = crypty.generate_key()
  return aes_cbc.infra.encrypt_manual(msg.encode("hex"), k1, iv) + iv

# For E
def step3_1(ciphertext):
  if gtype == 0:
    msg = aes_cbc.infra.decrypt_manual(ciphertext[0:-32], getSHA1(format(1, 'x'))[:32], ciphertext[-32:])
  elif gtype == 1:
    msg = aes_cbc.infra.decrypt_manual(ciphertext[0:-32], getSHA1(format(0, 'x'))[:32], ciphertext[-32:])
  elif gtype == 2:
    try:
      msg = aes_cbc.infra.decrypt_manual(ciphertext[0:-32], getSHA1(format(1, 'x'))[:32], ciphertext[-32:])
    except:
      msg = aes_cbc.infra.decrypt_manual(ciphertext[0:-32], getSHA1(format(E_knows['p'] - 1, 'x'))[:32],
                                         ciphertext[-32:])
  E_knows['msg1'] = msg.decode("hex")
  return ciphertext

# For B
def step4(msg):
  p = B_knows['p']
  A = B_knows['A']
  b = B_knows['b']
  k2 = getSHA1(format(pow(A,b,p),'x'))[0:32]
  B_knows['k2'] = k2
  B_knows['msg2'] = msg
  iv = crypty.generate_key()
  return aes_cbc.infra.encrypt_manual(msg.encode("hex"), k2, iv) + iv

# For E
def step4_1(ciphertext):
  if gtype == 0:
    msg = aes_cbc.infra.decrypt_manual(ciphertext[0:-32], getSHA1(format(1, 'x'))[:32], ciphertext[-32:])
  elif gtype == 1:
    msg = aes_cbc.infra.decrypt_manual(ciphertext[0:-32], getSHA1(format(0, 'x'))[:32], ciphertext[-32:])
  elif gtype == 2:
    try:
      msg = aes_cbc.infra.decrypt_manual(ciphertext[0:-32], getSHA1(format(1, 'x'))[:32], ciphertext[-32:])
    except:
      msg = aes_cbc.infra.decrypt_manual(ciphertext[0:-32], getSHA1(format(E_knows['p'] - 1, 'x'))[:32],
                                         ciphertext[-32:])
  E_knows['msg2'] = msg.decode("hex")
  return ciphertext

def solve():
  p, g, A = step1()   ### Original
  p, g, E = step1_1(p, g, A)   ### MITM
  B = step2(p, g, E)  ### Original
  E = step2_1(B)               ### MITM
  msg = "YOU ARE FUCKED"
  cipher1 = step3(msg, E)  ### Original
  step3_1(cipher1)  ### MITM
  cipher2 = step4(msg)
  step4_1(cipher2)
  print "Alice has : ",A_knows
  print "Bob has : ", B_knows
  print "Eve has : ",E_knows
  return

if __name__=='__main__':
  solve()