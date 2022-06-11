## Crypto/RSA-2
### Description
We are given the following:
```
N = 264057768287532610924734156161085846111271356228103155462076871372364307056741048144764594645062879781647063846971890031256799636109911752078600428566502298518944558664381187
e = 65537
ct = 175347248748800717331910762241898102719683222504200516534883687111045877096093372005991552193144558951747833811929393668749668731738201985792026669764642235225240342271148171
```
I immediately realized that N is way too small and we could probably factor it easily.

My first choice was [factordb.com](http://factordb.com/) which gives us the following:

![](factordb.PNG)
It doesn't give us the factorization but tells us that N is composite which we already know since N = P x Q for primes P and Q.

My next choice was [https://www.alpertron.com.ar/ECM.HTM](https://www.alpertron.com.ar/ECM.HTM) which gives us:

![](intfac.PNG)
We have found P and Q such that N = P x Q. Now we are pretty much done, we first calculate d which is the inverse of e modulo Φ(N) = (P-1)(Q-1). Now we raise our cypher text to the power of d mod N which gives us a decimal number that is the plaintext of the flag. We convert the decimal number to Hex and then decode into ASCII which gives us our flag : accessdenied{alw4y5_try_t0_f4ct0r1z3_n_9ba93547}
```
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
