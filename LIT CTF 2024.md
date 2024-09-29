
### Symmetric RSA (Crypto)

Handout : https://github.com/wLUOw/CTF_Writeups/tree/master/LIT_CTF_2024/file/Symmetric_RSA

#### Solution

We need to give plaintext, and the oracle will give out the corresponding ciphertext. Supppose we give -1 as the ciphertext
```
c = pow(-1, p, n)
Now since p is prime, it must be odd. So, (-1)^p = -1
c = -1 % n
c = n - 1
```

Just like that, we got the modulus = c + 1. Now, use m=2 and m=3 (use prime numbers reason given below), see below.
```
c1 = 2^p mod pq -> c1 = 2^p mod p  (Congruence Property)
c2 = 3^p mod pq -> c2 = 3^p mod p  (Congruence Property)

Using Fermats theorem,
2^p = 2 mod p
3^p = 3 mod p

So now,
c1 = 2 mod p -> p | c1 - 2
c2 = 3 mod p -> p | c2 - 3

So now,
p = GCD(c1-2, c2-3) 
Here if we didn't take prime numbers as chosen plaintext, we cannot guarantee that p will be the GCD
```

Once we obtain p, it is pretty trivial to decrypt the ciphertext.

**FLAG : LITCTF{ju57_u53_e=65537_00a144ca}**