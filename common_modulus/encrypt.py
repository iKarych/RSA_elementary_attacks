###############################################################

#################  Common Modulus Attack  #####################

##### Adapted from https://medium.com/bugbountywriteup/ #######
##### rsa-attacks-common-modulus-7bdb34f331a5 #################

###############################################################

from Crypto.Util.number import *
from Crypto.PublicKey import RSA
#from Crypto.Cipher import PKCS1_OAEP
import Crypto.Random

## Calculating values for 2 RSA pairs
while True:
    p = getPrime(512)
    q = getPrime(512)
    n = p*q
    # size() from Crypto.Util.number tells the size of the number (in bits)
    size1 = size(n)

    e1 = 13
    e2 = 15
    phin = (p-1)*(q-1)
    if (GCD(e1, phin) == 1 and GCD(e2, phin) == 1 and GCD(e1, e2) == 1):
        break

#d1 = inverse(e1, phin)
#d2 = inverse(e2, phin)

## Loading message
f = open("../lorem_ipsum.txt",'r')
string = f.read()
f.close()
string = string[:127]
flag = string.encode('utf-8').strip()

## Constructing 2 RSA pairs
publickey1 = RSA.construct((n, int(e1)))
#privatekey1 = RSA.construct((n, int(e1), int(d1)))

publickey2 = RSA.construct((n, int(e2)))
#privatekey2 = RSA.construct((n, int(e2), int(d2)))

## Crypting the message
random = Crypto.Random.get_random_bytes(5)
ciphertext1 = publickey1.encrypt(flag, random)
ciphertext2 = publickey2.encrypt(flag, random)

## Assuring that the condition for Common Modulus Attack is fullfilled
ciphertext2_long = bytes_to_long(ciphertext2[0])
assert GCD(ciphertext2_long, n) == 1


## Saving crypted message
obj1 = open("ciphertext1.txt",'w')
obj1.write(ciphertext1[0].hex())
obj1.close()

obj2 = open("ciphertext2.txt",'w')
obj2.write(ciphertext2[0].hex())
obj2.close()


#f = open("privatekey1.pem",'w')
#f.write(privatekey1.exportKey("PEM").decode("utf-8") )
#f.close()

#f = open("privatekey2.pem",'w')
#f.write(privatekey2.exportKey("PEM").decode("utf-8") )
#f.close()

## Saving public keys
f = open("publickey1.pem",'w')
f.write(publickey1.exportKey("PEM").decode("utf-8") )
f.close()

f = open("publickey2.pem",'w')
f.write(publickey2.exportKey("PEM").decode("utf-8") )
f.close()
