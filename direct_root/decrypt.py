###############################################################

##################  Direct Square Root  #######################

## Adapted from https://github.com/ashutosh1206/Crypton.git ##

###############################################################

from Crypto.Util.number import *
from Crypto.PublicKey import RSA
#from Crypto.Cipher import PKCS1_OAEP
import gmpy2

## Importing key
f = open('publickey.pem','r')
key = RSA.importKey(f.read())
f.close()

## Loading object
f = open("ciphertext.txt",'r')
cipher = bytes_to_long(bytes.fromhex(f.read()))
f.close()

## Attack
## Performing direct root using public exponent
message = gmpy2.iroot(cipher, key.e)
message = long_to_bytes(message[0]).decode()

print("Decoded message: ", message, "\n")
