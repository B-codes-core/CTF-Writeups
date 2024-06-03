
## 1. School Essay

#Crypto
#### Description
I had to write an essay for school describing my favorite classmate. I wonder if my classmates will be able to figure out who I'm describing...

#### Attachments

##### Description.txt
```
My Favorite Classmate
=====================

My favorite person in this class has a beautiful smile,
great sense of humour, and lots of colorful notebooks.

However, their most distinctive feature is the fact that
you can represent their name as an integer value, square
it modulo 
1839221045943946468749590061514704444096822140639024607242755810381377444892113085421174752142441, (m)
and you'll get 1804671962891598586831251656431345607187951389706305029952427287330950271224234433906630527235349. (c)

By now, all of you have probably guessed who I'm talking about.
```

#### Solution
Let x be the integer representation of the person. Given that
`x^2 mod m = c `

Now we need to find the [modular square root](https://www.rieselprime.de/ziki/Modular_square_root) of x.

Since the modulus m is prime, we can use the [Tonelli-Shanks Algorithm](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm)
If m was composite, we would use the Tonelli-Shanks Algorithm on the factors of m and use Chinese Remainder Theorem to find the final solution.

Use this python implementation : https://github.com/ZeroBone/TonelliShanks
Git clone the project, and make sure to include a `__init__.py`  
The empty `__init__.py` file communicates to the python interpreter that the developer intends this directory to be an importable package.

Run the below command
`python tonellishanks.py <c> <m>`

We will get a square root value : 703032588627510822704619969444615719158069204277139920487471397235396114708359092304587909772157

```
from Crypto.util.number import *
a = 703032588627510822704619969444615719158069204277139920487471397235396114708359092304587909772157
print(long_to_bytes(a))
```

**Flag :  TBTL{J0hn_J4c0b_J1n6leH31mer_Schm1d7_<3}**