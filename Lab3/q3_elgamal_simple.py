import random
import math


def gen_key(q):
    key = random.randint(10**20, q)
    while math.gcd(q, key) != 1:
        key = random.randint(10**20, q)
    return key

def encrypt(msg, q, h, g):
    en_msg = []
    k = gen_key(q)
    s = pow(h, k, q)
    p = pow(g, k, q)
    for i in range(len(msg)):
        en_msg.append(msg[i])
    for i in range(len(en_msg)):
        en_msg[i] = s * ord(en_msg[i])
    print("c2: ", en_msg,"\nc1: ", p)
    return en_msg, p

def decrypt(en_msg, p, key, q):
    dr_msg = []
    h = pow(p, key, q)
    for i in range(len(en_msg)):
        dr_msg.append(chr(int(en_msg[i] / h)))
    return "".join(dr_msg)

msg = "condom"
print("Original Message:", msg)
q = random.randint(10**20, 10**50)
g = random.randint(2, q)
key = gen_key(q)  # Private key for receiver
h = pow(g, key, q)
en_msg, p = encrypt(msg, q, h, g)
dr_msg = decrypt(en_msg, p, key, q)
print("Decrypted Message:", dr_msg)

