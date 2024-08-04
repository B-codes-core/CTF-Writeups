### Parrot the Emu - Web

First find out that it is SSTI server side template injection by testing {{7\*7}} Then by seeing the directory structure of website in handout, we see that we need to read contents of flag file Follow this article : [https://payatu.com/blog/server-side-template-injectionssti/](https://payatu.com/blog/server-side-template-injectionssti/ "https://payatu.com/blog/server-side-template-injectionssti/") In this one change is to be made. In our case, the class IOBase is not in subclassess\[111]. We need to print all classes in subclass, and find out the index of IOBase class. It is 92. Then use the below payload {{1337.class.mro\[1].subclasses()\[92].subclasses()\[0].subclasses()\[0]('flag').read()}}

### SAM I AM - Forensics 

We are given SAM file and SYSTEM file. We need to extract administrator password from it
`samdump2 SAM.bak SYSTEM.bak`
We get the hashed password. Use crackstation.net to get the password.

### Decrypt Then Eval - Crypto 

**Description :** This server decrypts user input and evaluates it. Please use your magical malleability mastership to retrieve the flag!

Handout : https://github.com/DownUnderCTF/Challenges_2024_Public/blob/main/crypto/decrypt-then-eval/publish/decrypt-then-eval.py

I thought that I took an easier approach to solve this problem, but little did I know that I accidentally took the longer route.

Seeing the code, we get to know that the encryption scheme used is AES in CFB mode. We need to provide a ciphertext, which the code decrypts and tries to run using eval and print it. We somehow need to pass in a ciphertext, such that it decrypts to `FLAG` so that the effective statement is `print(eval('FLAG'))` which will print the flag.

First let us understand how decryption works in AES-CFB. See this [Image](https://www.google.com/imgres?q=aes%20cfb%20mode%20decryption&imgurl=https%3A%2F%2Fi.stack.imgur.com%2F0pnXe.gif&imgrefurl=https%3A%2F%2Fcrypto.stackexchange.com%2Fquestions%2F42400%2Fis-it-possible-to-decrypt-the-2nd-byte-of-aes-256-cfb-8-ciphertext-without-decry&docid=ig59rlQJkeAzSM&tbnid=MCZ2Qu0iFUK_BM&vet=12ahUKEwiapvOVurOHAxX6ZWwGHZ_ICnoQM3oECFoQAA..i&w=601&h=242&hcb=2&ved=2ahUKEwiapvOVurOHAxX6ZWwGHZ_ICnoQM3oECFoQAA)

Since plaintext is only 4 bytes long ('FLAG'), we need to only focus on the first block. We see that first IV is encrypted, then it is XORed with the ciphertext to get the plaintext. This XOR operation is what makes AES-CFB a stream cipher.

Now my thought process was like this : If I somehow obtained the first 4 bytes of the encrypted IV, I can XOR them with the 4 bytes 'FLAG' to get a ciphertext. This way when we pass this ciphertext it is decrypted to 'FLAG' ( `enc_iv ^ ciphertext = plaintext, so ciphertext = enc_iv ^ plaintext` )

Now, I played a bit with the given handout code, I discovered that `eval(n) = n` where n is any number (This does not work for alphabets and special characters). This gave me an idea : we could try all 256 possible bytes as ciphertext and see if it decrypts to a number. If it decrypts to a number, it will print the number. Otherwise, the code will print 'invalid ct!'

Ex) Suppose the byte `b'\xe4'` decrypts to 1, then it becomes print(eval(1)) -> 1. Now we have a plaintext and ciphertext pair and we if XOR them both we will get the first byte of the encrypted IV!

Now we can brute-force the rest 3 bytes of the encrypted IV in a similar fashion, the only difference being that we try `b'\xe4\x00` to `b'\xe4\x255` to find the second byte. That is we append the bytes we are trying to the ciphertext that we already found out. Then we XOR the second byte of the obtained plaintext with the 2nd byte of the ciphertext to get the 2nd byte of the encrypted IV. Similarly we find 4 bytes of the IV

Once we get 4 bytes of encrypted IV, we could execute the plan I discussed above to obtain the ciphertext payload.

While testing the code that implements the above ideas, I found 2 pitfalls. (These took me so long to figure out 🥲)

- Firstly, suppose we get a byte that decrypts to `1` say. In the next iteration suppose, we get a comma, it becomes `1,` and `eval('1,')` returns a tuple, which derails our entire plans.

- Secondly, suppose we get a byte that decrypts to `1` say. In the next iteration suppose, we get a space or hash, then `eval('1 ')` and `eval('1#')` both give `1`, so we don't get a second byte here and we cannot find the second byte of the encrypted IV.

So I added two checks to ensure that the code does not bail out on me in such cases. Final code is given below.

```python
from Crypto.Cipher import AES
from pwn import *

conn = process(['python','decrypt-then-eval.py'])
#conn = remote('2024.ductf.dev', 30020)
#context.log_level = 'DEBUG'

def oracle(payload):
    conn.recvuntil(b': ')
    conn.sendline(payload.encode())
    response = conn.recvline()
    if(response.decode().strip() == 'invalid ct!'):
        return None
    return response

def get_enc_IV():
    iv = b''
    ciphertext = ''
    for i in range(4):
        print("[-] Finding Byte",i+1,"of IV :",end='')
        for j in range(256):
            response = oracle(ciphertext + bytes([j]).hex())
            try:
                int(response)   # To avoid anything that is becoming a tuple
            except Exception:   # int(<tuple>) will raise Exception
                continue
            if response != None and len(response.decode().strip()) == i+1:                                  # Second condition given to avoid the second case
                byte = j ^ ord(response.decode().strip()[-1])  
                print("Found ✓ (",bytes([byte]),")")
                iv += bytes([byte])
                ciphertext += bytes([j]).hex()
                break
    return iv


def main():
    iv = get_enc_IV()
    print('[✓] Found IV :',iv)
    reqd_text = b'FLAG'
    c = b''
    for i in range(4):
        c += bytes([reqd_text[i] ^ iv[i]])
    flag = oracle(c.hex())
    print("[✓] Flag Retrieved :",flag)

if __name__ == "__main__":
    main()
```

- There is a much better solution. We know that the numbers come at a stretch. That is if decryption of 0x156 is a number then decryption of 0x157, 0x158 and so on will also be a number. So we can make sure that we hit like 7 good evals at a stretch to guarantee that we are getting a number and we can avoid commas and hashes. The code for this implementation s much better and is given [here](https://github.com/DownUnderCTF/Challenges_2024_Public/blob/main/crypto/decrypt-then-eval/solve/solv.py)

### V for Vieta - Crypto 

Refer the source code here : https://github.com/DownUnderCTF/Challenges_2024_Public/blob/main/crypto/v-for-vieta/src/server.py

https://berliangabriel.github.io/post/ductf-2024/

We see that the server generates a random k. By looking at the code, we see that we need to provide a and b such that `(a**2 + a * b + b**2) / (2 * a * b + 1) == k`. Now in generate_k function, we see that k is the square of a random number. Now if you see, if we get the square root of a, let us say u, if we plug in u for a and 0 for b in the above given equation, we see that we are getting k. Problem Solved? No there is a catch.

We see that the function is also doing a further check, to ensure that both a and b are at least 2048 bits.  So now we have a solution, that we need to somehow expand to 2048 bits. This is where [Vieta Jumping](https://en.wikipedia.org/wiki/Vieta_jumping) comes in. It is used to produce new solutions of a quadratic Diophantine equation from known solution. 

See this [example](https://en.wikipedia.org/wiki/Vieta_jumping#Constant_descent_Vieta_jumping) especially. From this example, we get to know that if we have a solution (a,b) then the next solution is (b,x2) where x2 = k-ba. Now if we go ahead and compute k-ba we see that it is a little complex. So what we do is we substitute a = b in the equation to get x2. This way we get the next solution `(r, 2 * r ** 3 - r)`. Similarly we compute the next solution `(2 * r ** 3 - r , 4 * r ** 5 - 4 * r ** 3)`

Now we notice that the easy way to find the next solution is 
```
a[i] = b[i-1]
b[i] = (2 * r ** 2 - 1)*b[i-1] - a[i-1] 
```

Now we can write the code for the same.

```python
from pwn import *
from math import isqrt
import json

#conn = process(['python', 'Vieta.py'])
conn = remote('2024.ductf.dev' ,30018)

def get_k():
	data = json.loads(conn.recvline().decode())
	print(data)
	k = data["k"]
	return k

def get_ab(k):
	a = 0
	r = b = isqrt(k)
	while(a.bit_length() <= 2048 or b.bit_length() <= 2048):
		temp = a
		a = b
		b = (2 * r**2 - 1)*b - temp
	return (a,b)

def sanity_check(a,b,k):
	assert k == (a**2 + a*b + b**2)//(2*a*b + 1)

def main():
	conn.recvline()  # Get rid of first line
	while True:
		k = get_k()
		a,b = get_ab(k)
		sanity_check(a,b,k)
		ans = json.dumps({"a" : a, "b" : b}).encode()
		conn.sendline(ans)

if __name__ == "__main__":
	main()
```

