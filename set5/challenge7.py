"""
Main Code
"""

from Crypto.Util.number import getPrime

def generatePrime(bits):
  return getPrime(bits)

'''From https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Recursive_method_2

Returns (x,y) such that (ax + by) = gcd(a,b)'''


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


def solve1():
  p = 71
  q = 83
  N = p*q
  phi = (p-1)*(q-1)
  e = 3
  d = invmod(e,phi)
  msg = 42
  encrypted = pow(msg, e, N)
  decrypted = pow(encrypted, d,N)
  assert decrypted == msg
  return

### phi and e must be co-primes
def solve2():
  e = 3
  p = generatePrime(1024)
  while (p%e)==1 :
    p = generatePrime(1024)
  q = generatePrime(1024)
  while (q%e)==1:
    q = generatePrime(1024)
  N = p*q
  phi = (p-1)*(q-1)
  d = invmod(e,phi)
  msg = 42
  encrypted = pow(msg, e, N)
  decrypted = pow(encrypted, d,N)
  assert decrypted == msg
  return


if __name__ == '__main__':
  solve1()
  solve2()
