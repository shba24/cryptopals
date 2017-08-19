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
  E_knows['g'] = g
  E_knows['A'] = A
  e = random.randint(2,p)
  E = pow(g, e, p)
  E_knows['e'] = e
  E_knows['E'] = E
  return (p,g,E)

# For B
def step2(p,g,A):
  B_knows['p'] = p
  B_knows['g'] = g
  B_knows['A'] = A
  b = random.randint(2,p)
  B = pow(g, b, p)
  B_knows['b'] = b
  B_knows['B'] = B
  B_knows['k2'] = getSHA1(format(pow(A,b,p),'x'))[0:32]
  return B

# For E
def step2_1(B):
  E_knows['B'] = B
  k1 = pow(E_knows['A'],E_knows['e'],E_knows['p'])
  k1 = getSHA1(format(k1,'x'))[:32]
  k2 = pow(E_knows['B'],E_knows['e'],E_knows['p'])
  k2 = getSHA1(format(k2, 'x'))[:32]
  E_knows['k1'] = k1
  E_knows['k2'] = k2
  return E_knows['E']

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
def step3_1(ciphertext, inject=None):
  msg = aes_cbc.infra.decrypt_manual(ciphertext[0:-32], E_knows['k1'], ciphertext[-32:])
  E_knows['msg'] = msg.decode("hex")
  iv = crypty.generate_key()
  if inject:
    E_knows['inject'] = inject
    msg = inject.encode("hex")
  return aes_cbc.infra.encrypt_manual(msg, E_knows['k2'], iv) + iv

# For B
def step4(ciphertext):
  msg = aes_cbc.infra.decrypt_manual(ciphertext[0:-32], E_knows['k2'], ciphertext[-32:])
  B_knows['msg'] = msg.decode("hex")
  return

def solve():
  p, g, A = step1()   ### Original
  p, g, E = step1_1(p, g, A)   ### MITM
  B = step2(p, g, E)  ### Original
  E = step2_1(B)               ### MITM
  msg = "YOU ARE SAFE"
  cipher1 = step3(msg, E)  ### Original
  cipher2 = step3_1(cipher1, inject='YOU ARE FUCKED')  ### MITM
  step4(cipher2)
  print "Alice has : ",A_knows
  print "Bob has : ", B_knows
  print "Eve has : ",E_knows
  return

if __name__=='__main__':
  solve()