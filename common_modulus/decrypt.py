###############################################################

#################  Common Modulus Attack  #####################

##### Adapted from https://medium.com/bugbountywriteup/ #######
##### rsa-attacks-common-modulus-7bdb34f331a5 #################

###############################################################

from Crypto.Util.number import *
from Crypto.PublicKey import RSA
#from Crypto.Cipher import PKCS1_OAEP

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


## Load public keys and crypted message
publickey = []
cipher = []

for i in range(1,3):
    f = open("publickey" + str(i) + ".pem",'r')
    publickey.append(RSA.importKey(f.read()))
    f.close()

    f = open("ciphertext" + str(i) + ".txt",'r')
    cipher.append(bytes_to_long(bytes.fromhex(f.read())))
    f.close()

## Check assumptions
assert GCD(publickey[0].e, publickey[1].e) == 1, "public exponents must be coprime"
assert GCD(cipher[1], publickey[0].n) == 1, "message and modulus must be coprime"
assert publickey[0].n == publickey[1].n, "modulus must be the same"

## Attack
## xe_1 + ye_2 = 1
x = modinv(publickey[0].e, publickey[1].e)
y = (GCD(publickey[0].e, publickey[1].e) - publickey[0].e * x) / publickey[1].e
y_inverse = modinv(cipher[1], publickey[0].n)
c1 = pow(cipher[0],x,int(publickey[0].n))
c2 = pow(int(y_inverse),int(-y),int(publickey[0].n))
message = (c1 * c2) % publickey[0].n

print("Decoded message: ", long_to_bytes(message).decode(), "\n")

