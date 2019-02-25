from zkPAKEImplementation import protocol
import groups
import hashlib
import itertools
from tqdm import tqdm
import time
import numpy as np
import random
N,u,chelp = protocol()

#Adversary listens to zkPAKE protocol and when he obtains N,u, H1(c) goes offline and performs dictionary attack

#Checking every password candidate pw', computing H1(pw'), c' and H1(c'), then checking if H1(c') match H1(c)
def check_password(pw_candidate):
    bytePw = pw_candidate.encode() 
    #Hash of a password
    H1 = hashlib.sha256(bytePw).hexdigest()
    Hpw = int(H1,16)
    r = Hpw % q
   
    #Computing v from the formula
    v = (u + cint*r ) % q
    #Computing t from the formula
    t = pow(N,v,p)
    #Computing R from the formula
    R = pow(g,r,p)

    #Hashing H1(g,g^r,t,N), Remark: For simplicity instead of g^r we use R
    g_bytes = g.to_bytes(n_bytes,'big')
    R_bytes = R.to_bytes(n_bytes,'big')
    t_bytes = t.to_bytes(n_bytes,'big')
    N_bytes = N.to_bytes(n_bytes,'big')
    gRtN_bytes_concat = g_bytes+R_bytes+t_bytes+N_bytes
    # H(c_candidate)
    c_candidate_help = hashlib.sha256(gRtN_bytes_concat).hexdigest() 
    #Computing H1(c_candidate)
    c_candidate = hashlib.sha256(c_candidate_help.encode()).hexdigest()
    #checking if the password is correct
    return chelp == c_candidate
    if chelp == c_candidate :
          print("password found",pw_candidate)
    # else : print("password not found, try another candidate")




#Get public group parameters
i = 2
p = groups.getP(i)
q = groups.getQ(i)
g = groups.getG(i)
# number of bytes
n_bytes = 256
#Converting H1(c) into integer
cint = int(chelp,16) % q

#Checking the password from the same dictionary, changing samples of 1k,10k and 100k passwords
#To achive average and standard deviation we shuffle passwords each time,50 times each sample
def discover(content, lensize):
    tmp_content = content[0:lensize]
    tmp_content.append("metal")
    random.shuffle(tmp_content)

    time_c = 0
    start = time.time()
    for pw_candidate in tmp_content:
        #print(pw_candidate)
        if not pw_candidate.strip(): #len(pw.strip())<1:
            continue
        if check_password(pw_candidate):
            end = time.time()
            time_c = end-start
            #print("cost: ", time_c)
            break
    return time_c

def test(n_num, lensize):
    time_measurements = []
    for ix in range(n_num):
        print("Test begin: ", str(lensize), "at :", str(ix))
        time_c = discover(contents,lensize)
        if time_c:
            time_measurements.append(time_c)
    if time_measurements:
        print("Total for ", str(lensize), " :", np.sum(time_measurements)," average:",np.mean(time_measurements)," std:",np.std(time_measurements))
    else:
        print("the pwd is not found.")


if __name__ == '__main__':

    file_path = "dictionary_example.txt"
    time_measurements = []
    #encoding="Latin-1"
    with open(file_path, errors="ignore") as f:
        content = f.readlines()
    #100k
    contents = [line[:-1] for line in content]

    n_num = 50
    #test 1k
    test(n_num,1000)
    #test 10k
    test(n_num,10000)
    #test 100k
    test(n_num,100000)





