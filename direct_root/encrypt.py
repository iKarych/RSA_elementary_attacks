###############################################################

##################  Direct Square Root  #######################

## Adapted from https://github.com/ashutosh1206/Crypton.git ##

###############################################################

from Crypto.Util.number import *
from Crypto.PublicKey import RSA
#from Crypto.Cipher import PKCS1_OAEP
import Crypto.Random


## Getting key pair
while True:
    p = getPrime(512)
    q = getPrime(512)
    n = p*q

    e = 3
    phin = (p-1)*(q-1)
    if GCD(e, phin) == 1:
        break

#d = inverse(e, phin)

## Loading message
f = open("../lorem_ipsum.txt",'r')
string = f.read()
f.close()
string = string[:20]
flag = string.encode('utf-8').strip()

## Constructing key
publickey = RSA.construct((n, int(e)))
#privatekey = RSA.construct((n, int(e), int(d)))

## Crypting message
random = Crypto.Random.get_random_bytes(8)
ciphertext = publickey.encrypt(flag, random)

## Saving crypted message
f = open("ciphertext.txt",'w')
f.write(ciphertext[0].hex())
f.close()

## Saving public key
f = open("publickey.pem",'w')
f.write(publickey.exportKey("PEM").decode("utf-8") )
f.close()
