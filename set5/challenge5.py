"""
Main Code.
"""
import sys
import os
import crypty
import gmpy2
from crypty.hash import hash_sha256, hmac
from gmpy2 import mpz,powmod
from Crypto.Random import random
from Crypto.Hash import SHA256

N = mpz(0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff)
g = 2
k = 3
M = "shubbans@adobe.com"
P = "password"
rstate = gmpy2.random_state()
Server = {}
Client = {}

def generate_hash(salt, data):
    return hash_sha256(salt+data)

# Server side
def step_1():
    salt = str(crypty.get_salt())
    xH = generate_hash(salt, P)
    x = mpz(int(xH, 16))
    v = powmod(g, x, N)
    Server['salt'] = salt
    Server['v'] = v
    return

# Client Side
def step_2():
    a = gmpy2.mpz_random(rstate, N)
    A = powmod(g, a, N)
    Client['A'] = A
    Client['a'] = a
    Client['M'] = M
    return (M, A)

# Server Side
def step_3(M, A):
    Server['M'] = M
    Server['A'] = A
    b = gmpy2.mpz_random(rstate, N)
    B = (k * Server['v']) + powmod(g, b, N)
    Server['b'] = b
    Server['B'] = B
    return (Server['salt'], B)

# Server and Client Side
def step_4(salt, B):
    Client['salt'] = salt
    Client['B'] = B
    Client['u'] = mpz(int(generate_hash(str(Client['A']), str(B)), 16))
    Server['u'] = mpz(int(generate_hash(str(Server['A']), str(B)), 16))
    return

# Client Side
def step_5(passwd=P, _S=-1):
    x = mpz(int(generate_hash(Client['salt'], passwd), 16))
    if _S == -1:
        S = powmod((Client['B'] - (k*powmod(g, x, N))), Client['a'] + (Client['u']*x), N)
    else:
        S = _S
    K = hash_sha256(str(S))
    Client['K'] = K
    return

# Server side
def step_6():
    S = powmod(Server['A'] * powmod(Server['v'], Server['u'], N), Server['b'], N)
    K = hash_sha256(str(S))
    Server['K'] = K
    return

# Client Side
def step_7():
    return hmac(Client['K'], Client['salt'], hash_function=hash_sha256)

# Server Side
def step_8(hash):
    if hmac(Server['K'], Server['salt'], hash_function=hash_sha256) == hash:
        return "OK"
    else:
        return "NOT OK"

def srp(passwd):
    step_1()
    M, A = step_2()
    salt, B = step_3(M, A)
    step_4(salt, B)
    step_5(passwd=passwd)
    step_6()
    hash = step_7()
    if step_8(hash) == "OK":
        return True
    else:
        return False
    return False

def solver():
    step_1()
    M, A = step_2()
    A = 0
    salt, B = step_3(M, A)
    step_4(salt, B)
    step_5(_S=0)
    step_6()
    hash = step_7()
    print step_8(hash)
    return

if __name__=='__main__':
    solver()