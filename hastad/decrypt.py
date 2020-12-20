###############################################################

###############  Hastad's Broadcast Attack  ###################

## Adapted from https://github.com/ashutosh1206/Crypton.git ##

###############################################################

from Crypto.Util.number import *
from Crypto.PublicKey import RSA
#from Crypto.Cipher import PKCS1_OAEP
import gmpy2

## Extended Euclidean algorithm
def extendedGCD(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extendedGCD(b % a, a)
        return (g, x - (b // a) * y, y)

## Modular division (inversion)
def modinv(a, n):
    g, x, y = extendedGCD(a, n)
    if g != 1:
        raise ValueError('Modular inverse does not exist.')
    else:
        return x % n
    
#Chinese remainder theorem
def CRT(list_a, list_n):
    ## Checking if all the conditions are fullfilled
    assert len(list_a) == len(list_n), "Length of messages should be equal to length of modules"

    for i in range(len(list_n)):
        for j in range(len(list_n)):
            if GCD(list_n[i], list_n[j])!= 1 and i!=j:
                print("Moduli should be pairwise co-prime")
                return -1
   
    ## Getting common modulus - multiplication
    N = 1
    for i in list_n:
        N *= i
        
    ## Getting b_i = N/n_i
    list_b = [N//i for i in list_n]
    assert len(list_b) == len(list_n)
    
    ## Getting inverse of b_i
    list_b_inv = [int(modinv(list_b[i], list_n[i])) for i in range(len(list_n))]

    ## Getting the result
    x = 0
    for i in range(len(list_n)):
        x += list_a[i]*list_b[i]*list_b_inv[i]
    return x % N

    
## Prepare variables
list_publickey_n = []
list_cipher = []
i = 0

## Load keys and crypted messages
while True:
    try:
        f_cipher = open("cipher/ciphertext" + str(i) + ".txt",'r')
        list_cipher.append(bytes_to_long(bytes.fromhex(f_cipher.read())))
        f_cipher.close()
        
        f_key = open("pubkey/publickey" + str(i) + ".pem",'r')
        public_key = RSA.importKey(f_key.read())
        list_publickey_n.append(public_key.n)
        e = public_key.e
        f_key.close()
        
        i = i + 1
    except:
        break
    
## Attack
## Chinese Remainer Theorem
m = CRT(list_cipher, list_publickey_n)
## Take root
message = long_to_bytes(gmpy2.iroot(m, e)[0])

print("Decoded message: ", message.decode(), "\n")

