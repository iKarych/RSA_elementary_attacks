###############################################################

###############  Hastad's Broadcast Attack  ###################

## Adapted from https://github.com/ashutosh1206/Crypton.git ##

###############################################################

from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import Crypto.Random
import shutil
import os

## Preparing variables
e = 3
list_n = []
list_publickey = []
list_cipher = []

## Loading message
random = Crypto.Random.get_random_bytes(8)
f = open("../lorem_ipsum.txt",'r')
string = f.read()
f.close()
string = string[:127]
flag = string.encode('utf-8').strip()

## Creating e pairs of keys and making sure that their modulus' are coprime
while True:
    p = getPrime(512)
    q = getPrime(512)
    
    coprime = True
    for n in list_n:
        if GCD(n,p*q) != 1:
            coprime = False
    
    if coprime:
        list_n.append(p*q)
        public_key = RSA.construct((p*q, int(e)))
        list_publickey.append(public_key)
        list_cipher.append(public_key.encrypt(flag, random)[0].hex())
    
    if len(list_n) == e:
        break
    
## Saving crypted message and public keys
shutil.rmtree('cipher', ignore_errors=True)
shutil.rmtree('pubkey', ignore_errors=True)
os.mkdir("cipher")
os.mkdir("pubkey")

for i in range(len(list_n)):
    f_cipher = open("cipher/ciphertext" + str(i) + ".txt",'w')
    f_cipher.write(list_cipher[i])
    f_cipher.close()
    
    f_key = open("pubkey/publickey" + str(i) + ".pem",'w')
    f_key.write(list_publickey[i].exportKey("PEM").decode("utf-8") )
    f_key.close()
