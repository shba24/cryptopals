"""
Main Code.
"""
from crypty import a2h, h2a
from gmpy2 import is_prime, mpz, mpz_random, random_state, invert, t_mod, powmod
from Crypto.Random import random
from Crypto.Hash import SHA
from Crypto.Util.number import getPrime

rstate = random_state()

def getSHA1(MSG):
  h = SHA.new()
  h.update(MSG)
  return h.hexdigest()

def generatePrime(bits):
  return mpz(getPrime(bits))

def genP(L, q):
    minK = (pow(2, L-1) + (q-1))//q
    maxK = (pow(2, L) - 1)//q
    while True:
        k = mpz_random(rstate, maxK - minK) + minK
        p = k*q + 1
        if is_prime(p):
            return (k, p)

def genG(p, q, k):
    h = 2
    while h<p-1:
        g = pow(h, k, p)
        if g!=1:
            return g
        h+=1
    return None

def genParams(L, N):
    q = generatePrime(N)
    k, p = genP(L, q)
    g = genG(p, q, k)
    return (p, q, g)

def genKeys(p, q, g, B=None):
    priv = None
    if B is None:
        d = mpz_random(rstate, q-1) + 1
        priv = d
        B = pow(g, d, p)
    pub = (p, q, g, B)
    return (pub, priv)

def signDSA(message, pub, priv, kE=None):
    (p, q, g, B) = pub
    d = priv
    H = mpz(getSHA1(message), base=16)
    while True:
        if kE is None:
            # Ephemeral key
            kE = mpz_random(rstate, q-1) + 1
        r = t_mod(pow(g, kE, p), q)
        s = t_mod(((H + (d*r)) * invert(kE, q)), q)
        return (r, s)
    return (None, None)

def verifySign(sig, message, pub):
    (p, q, g, B) = pub
    (r, s) = sig
    s_inv = invert(s, q)
    H = mpz(getSHA1(message), base=16)
    u1 = t_mod(s_inv * H, q)
    u2 = t_mod(s_inv * r, q)
    v = t_mod(t_mod(powmod(g, u1, p) * powmod(B, u2, p), p), q)
    if v == t_mod(r, q):
        return True
    else:
        return False
    return False

def solver():
    msg1 = b"Hello, world"
    msg2 = b"Goodbye, world"
    L = mpz(1024)
    N = 160
    (p, q, g) = genParams(L, N)
    # p = mpz("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", base=16)
    # q = mpz("f4f47f05794b256174bba6e9b396a7707e563c5b", base=16)
    # g = mpz("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", base=16)
    (pub, priv) = genKeys(p, q, 0)
    sig1 = signDSA(msg1, pub, priv)
    sig2 = signDSA(msg2, pub, priv)
    assert verifySign(sig1, msg1, pub)
    assert verifySign(sig2, msg2, pub)
    assert verifySign(sig1, msg2, pub)
    assert verifySign(sig2, msg1, pub)

    # if we put g = p + 1, new r value will be 1
    (pub, priv) = genKeys(p, q, p+1)
    new_r = 1
    new_s = t_mod(invert(2, q), q)
    signature = (new_r, new_s)
    assert verifySign(signature, msg1, pub)
    assert verifySign(signature, msg2, pub)
    return

if __name__=="__main__":
    solver()