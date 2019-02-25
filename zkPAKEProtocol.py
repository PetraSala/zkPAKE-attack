import groups
import hashlib
import random
import numpy as np

import hmac
from math import ceil


#zkPAKE protocol
#testing offline dictionary attack
def protocol(seed=0):
    #set size Groups
    #Group 1: 1024-bit MODP Group with 160-bit Prime Order Subgroup
    #Group 2: 2048-bit MODP Group with 224-bit Prime Order Subgroup
    i=2 
    random.seed(seed)
     #Get public group parameters
    p = groups.getP(i)
    q = groups.getQ(i)
    g = groups.getG(i)
  
    # number of bytes
    n_bytes = 256

    pw = "metal"
    bytePw = pw.encode() 
    #Hash of a password
    H1 = hashlib.sha256(bytePw).hexdigest()
    #Hash converted to int
    Hpw = int(H1,16)
    r = Hpw % q
    #Server 
    R = pow(g,r,p)
    #Server stores R and chooses a random number n and calculates
    n = random.randint(1,q)
    N = pow(g,n,p)
    # Server sends N to the Client

    #Client
    #Client knows pw and r
    v = random.randint(1,q)
    t = pow(N,v,p)
    #Hashing H1(g,g^r,t,N), Remark: For simplicity instead of g^r we use R
    g_bytes = g.to_bytes(n_bytes,'big')
    R_bytes = R.to_bytes(n_bytes,'big')
    t_bytes = t.to_bytes(n_bytes,'big')
    N_bytes = N.to_bytes(n_bytes,'big')
    gRtN_bytes_concat = g_bytes+R_bytes+t_bytes+N_bytes
    c = hashlib.sha256(gRtN_bytes_concat).hexdigest()
    #Computing H1(c)
    chelp = hashlib.sha256(c.encode()).hexdigest()
    #Converting H1(c) into integer
    cint = int(chelp,16) % q
    #Client computes u
    u = v - (cint*r  % q)
    #Client computes session key, H2(chelp) 
    skc = hkdf(256,c.encode())
    #Client sends u, H1(c) to the Server
    #Server computes t1
    thelp = (u*n) % q
    thelp1 = (n*cint) % q
    t1 = (pow(g,thelp,p)*pow(R,thelp1,p)) % p
    #Server computes H1(g,R,t1,N)
    #g_bytes = g.to_bytes(n_bytes,'big')
    #R_bytes = R.to_bytes(n_bytes,'big')
    t1_bytes = t1.to_bytes(n_bytes,'big')
    #N_bytes = N.to_bytes(n_bytes,'big')
    gRtN_bytes_concat1 = g_bytes+R_bytes+t1_bytes+N_bytes
    c1 = hashlib.sha256(gRtN_bytes_concat1).hexdigest()
    # Server checks if H1(c1)==H1(c)
    #Server computes session key sks
    sks = hkdf(256,c1.encode())
    
    # if t1==t :
    #      print("match")
    # else : print("no match")

    # if hmac.compare_digest(sks,skc) :
    #      print("Session keys are the same")
    # else : print("Session keys are not equal")


    return (N,u,chelp)
hash_len = 32

#implementing key derivation function to compute session key
def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()

def hkdf(length, ikm, salt=b"", info=b""):
    prk = hmac_sha256(salt, ikm)
    t = b""
    okm = b""
    for i in range(ceil(length / hash_len)):
        t = hmac_sha256(prk, t + info + bytes([1+i]))
        okm += t
    return okm[:length]


if __name__== "__main__":
  protocol()
