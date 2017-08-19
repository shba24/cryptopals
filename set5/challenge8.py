"""
Main Code.
"""
import gmpy2
from crypty import a2h, h2a
from gmpy2 import mpz,powmod, t_mod, invert, iroot
from Crypto.Util.number import getPrime

def generatePrime(bits):
  return mpz(getPrime(bits))

### phi and e must be co-primes
def RSA(message):
  e = 3
  p = generatePrime(128)
  while (p%e)==1 :
    p = generatePrime(128)
  q = generatePrime(128)
  while (q%e)==1:
    q = generatePrime(128)
  N = p*q
  phi = (p-1)*(q-1)
  d = invert(e,phi)
  msg = mpz(a2h(message), base=16)
  encrypted = pow(msg, e, N)
  return (encrypted, e, N)

def e_3_broadcast_attack(public_key1, public_key2, public_key3):
    enc1, e1, n1 = public_key1
    enc2, e2, n2 = public_key2
    enc3, e3, n3 = public_key3
    N = n1 * n2 * n3
    result = t_mod((enc1 * (N/n1) * invert(N/n1, n1)) + \
                (enc2 * (N/n2) * invert(N/n2, n2)) + \
                (enc3 * (N/n3) * invert(N/n3, n3)), N)
    result = iroot(result, 3)
    return result[0]

def solver():
    enc1, e1, n1 = RSA("A"*20)
    enc2, e2, n2 = RSA("A"*20)
    enc3, e3, n3 = RSA("A"*20)
    result = e_3_broadcast_attack((enc1, e1, n1), (enc2, e2, n2), (enc3, e3, n3))
    assert h2a(format(result, "x")) == "A"*20
    return

if __name__=='__main__':
    solver()