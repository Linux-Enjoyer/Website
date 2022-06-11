## Crypto/RSA-2

We are given the following:
```
N = 264057768287532610924734156161085846111271356228103155462076871372364307056741048144764594645062879781647063846971890031256799636109911752078600428566502298518944558664381187
e = 65537
ct = 175347248748800717331910762241898102719683222504200516534883687111045877096093372005991552193144558951747833811929393668749668731738201985792026669764642235225240342271148171
```
We immediately realize that N is way too small and we could probably factor it easily.

My first choice was [factordb.com](http://factordb.com/) which gives us the following:

![](factordb.PNG)
It doesn't give us the factorization but tells us that N is composite which we already know since N = P x Q for primes P and Q.

My next choice was [https://www.alpertron.com.ar/ECM.HTM](https://www.alpertron.com.ar/ECM.HTM) which gives us:

![](intfac.PNG)
We have found P and Q such that N = P x Q. Now we are pretty much done, we first calculate d which is the inverse of e modulo Φ(N) = (P-1)(Q-1). Now we raise our ciphertext to the power of d mod N which gives us a decimal number that is the plaintext of the flag. We convert the decimal number to Hex and then decode into ASCII which gives us our flag : accessdenied{alw4y5_try_t0_f4ct0r1z3_n_9ba93547}
```python
n   = 264057768287532610924734156161085846111271356228103155462076871372364307056741048144764594645062879781647063846971890031256799636109911752078600428566502298518944558664381187
p   = 22788121468146346999
q   = 11587518025855592759726630124584244020238845252808598255278658263482784394605886754984976163579618331619323699778956049111427022474635415206131197278729813
phi = (p-1) * (q-1)
e   = 65537
ct  = 175347248748800717331910762241898102719683222504200516534883687111045877096093372005991552193144558951747833811929393668749668731738201985792026669764642235225240342271148171
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

assert(p*q==n)
d = modinv(e,phi)
print(pow(ct,d,n))
```
## Crypto/Small key

We are given the following:

```python
import os

flag = b"XXXXXX"
key = os.urandom(8)

cipher_text = b""

for i in range(len(flag)):
    cipher_text += bytes([flag[i] ^ key[i % 8]])


print(cipher_text.hex())


# flag 763d32726973a23f79373473616ba86a60300e677634f734482a626f6e5ff22e636a327c2f5ff228240123242e6caa23483d6127765fff6d743a61212f38bb
```
We observe that the key used for the One-time pad is only 8 bytes. Since each byte is decoded into 1 UTF-8 character we know that our key is exactly 8 characters long.

We also know the first 8 characters of the plaintext are going to be "accessde" since the flag format is accessdenied{}. With this knowledge can leak the entire key
by XORing the first 8 characters of the flag (after converting it from Hex to a byte object) with b"accessde". Now we use the key to decrypt the flag which gives us our flag:
accessdenied{kn0wn_pl41n_t3xt_4tt4ck5_4r3_r34lly_c00l_97cd0658}
```python
import binascii


flag = binascii.unhexlify("763d32726973a23f79373473616ba86a60300e677634f734482a626f6e5ff22e636a327c2f5ff228240123242e6caa23483d6127765fff6d743a61212f38bb")
starting_8_bytes_of_flag = binascii.unhexlify("763d32726973a23f")
starting_8_bytes_of_plaintext= b"accessde"
key = b""
for i in range(len(starting_8_bytes_of_flag)):
    key += bytes([starting_8_bytes_of_flag[i] ^ starting_8_bytes_of_plaintext[i % 8]]) 

plain = b""
for i in range(len(flag)):
    plain += bytes([flag[i] ^ key[i % 8]])
print(plain.decode())
```
