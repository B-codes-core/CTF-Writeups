## 1. Do Math!

#Crypto 
#### Description
We need to... do math... as cybersecurity people?
Handouts :
```
from Crypto.Util.number import *
p = getPrime(2048)
q = getPrime(2048)
e = 655537
n = p * q
d = pow(e, -1, (p-1)*(q-1))
msg = "byuctf{REDACTED}"
m = bytes_to_long(msg.encode('utf-8'))
c = pow(m, e, n)
print(c)
print()
hints = [p, q, e, n, d]
for _ in range(len(hints)):
    hints[_] = (hints[_] * getPrime(1024)) % n
    if hints[_] == 0: hints[_] = (hints[_] - 1) % n
print("Hints:")
print(hints)
```

See [hints.txt](file:///C%3A%2FUsers%2Fbalaj%2FOneDrive%2FDesktop%2FCTFs%2FBYUCTF%2FCrypto)
#### Solution
We can see that p and q are generated randomly, and hence that is not where the exploit lies. We concentrate on the part where hints are printed. The values are first multiplied by a random prime and then mod n is taken. Also, there is an if condition which checks if the value becomes 0 that is, if the calculated value is a multiple of n.
This is where I got the spark. n multiplied by any number must be a multiple of n and hence hints value for n should be n-1 according to the statement in the if condition. So we are indirectly given the n value.
Plugging the value of n in FactorDB, we get p and q and from there on we solve it just like normal RSA.

**Flag : byuctf{th3_g00d_m4th_1snt_th4t_h4rd}**

## 2. Are Yes A

#Crypto 
#### Description
n =  128393532851463575343089974408848099857979358442919384244000744053339479654557691794114605827105884545240515605112453686433508264824840575897640756564360373615937755743038201363814617682765101064651503434978938431452409293245855062934837618374997956788830791719002612108253528457601645424542240025303582528541
e =  65537
c =  93825584976187667358623690800406736193433562907249950376378278056949067505651948206582798483662803340120930066298960547657544217987827103350739742039606274017391266985269135268995550801742990600381727708443998391878164259416326775952210229572031793998878110937636005712923166229535455282012242471666332812788
#### Solution
Putting the value of n in FactorDB, it says that n is 100% prime. So we cannot split n. Instead we need to calculate phi(n) = n-1 (For prime numbers, value of totient function is p-1). Using this phi, we do normal RSA
**Flag : byuctf{d1d_s0m3_rs4_stuff...m1ght_d3l3t3_l4t3r}**




