For handouts of all challenges refer - https://github.com/ImaginaryCTF/ImaginaryCTF-2024-Challenges-Public

### Base64 - Crypto 

```python
from Crypto.Util.number import *
q = 64
secret_key = [10, 52, 23, 14, 52, 16, 3, 14, 37, 37, 3, 25, 50, 32, 19, 14, 48, 32, 35, 13, 54, 12, 35, 12, 31, 29, 7, 29, 38, 61, 37, 27, 47, 5, 51, 28, 50, 13, 35, 29, 46, 1, 51, 24, 31, 21, 54, 28, 52, 8, 54, 30, 38, 17, 55, 24, 41, 1]
flag = 0
for i in reversed(secret_key):
    flag = flag * q + i
print(long_to_bytes(flag))
```
### Integrity - Crypto 

```python
from Crypto.Util.number import **

n = 10564138776494961592014999649037456550575382342808603854749436027195501416732462075688995673939606183123561300630136824493064895936898026009104455605012656112227514866064565891419378050994219942479391748895230609700734689313646635542548646360048189895973084184133523557171393285803689091414097848899969143402526024074373298517865298596472709363144493360685098579242747286374667924925824418993057439374115204031395552316508548814416927671149296240291698782267318342722947218349127747750102113632548814928601458613079803549610741586798881477552743114563683288557678332273321812700473448697037721641398720563971130513427

ct = 5685838967285159794461558605064371935808577614537313517284872621759307511347345423871842021807700909863051421914284950799996213898176050217224786145143140975344971261417973880450295037249939267766501584938352751867637557804915469126317036843468486184370942095487311164578774645833237405496719950503828620690989386907444502047313980230616203027489995981547158652987398852111476068995568458186611338656551345081778531948372680570310816660042320141526741353831184185543912246698661338162113076490444675190068440073174561918199812094602565237320537343578057719268260605714741395310334777911253328561527664394607785811735

signature = 1275844821761484983821340844185575393419792337993640612766980471786977428905226540853335720384123385452029977656072418163973282187758615881752669563780394774633730989087558776171213164303749873793794423254467399925071664163215290516803252776553092090878851242467651143197066297392861056333834850421091466941338571527809879833005764896187139966615733057849199417410243212949781433565368562991243818187206912462908282367755241374542822443478131348101833178421826523712810049110209083887706516764828471192354631913614281317137232427617291828563280573927573115346417103439835614082100305586578385614623425362545483289428  

# ct = pow(flag,e1,n)  signature = pow(flag,e2,n)   Common Modulus Attack
# e1 = 65537   e2 is 16 bits, can brute-force
# https://blog.0daylabs.com/2015/01/17/rsa-common-modulus-attack-extended-euclidean-algorithm/
# gcd(e1,e2) = 1 (Reason is given in website)

def gcdExtended(a, b):
    # Base Case
    if a == 0 :
        return b,0,1
    gcd,x1,y1 = gcdExtended(b%a, a)
    # Update x and y using results of recursive
    # call
    x = y1 - (b//a) * x1
    y = x1
    return gcd,x,y

e = 65537
for i in range(2,65536):
    print(i)
    gcd,x,y = gcdExtended(e,i)
    if(gcd != 1):
        continue  
    c2i = pow(signature,-1,n)  # signature is c2, ct is c1
    plaintext = (pow(ct,x,n) * pow(c2i,-1 *y,n))%n  #Read website about why we have taken c2 inverse
    try:
        plaintext = long_to_bytes(plaintext).decode()
    except:
        continue
    if(plaintext.startswith('ictf')):
        print("Flag found :",plaintext)
        break
```

### Tango - Crypto

We have been given a stream cipher. We can extract the keystream and use that to modify the JSON and get the flag
```python
from Crypto.Util.number import *
from pwn import *
from zlib import crc32
import json

#conn = process(['python','server.py'])
conn = remote('tango.chal.imaginaryctf.org', 1337)

def get_encrypted_packet():
    conn.recvuntil(b'> ')
    conn.sendline(b'E')
    conn.recvuntil(b': ')
    conn.sendline(b'nop')
    conn.recvuntil(b': ')
    enc_packet = conn.recvline()
    return bytes.fromhex(enc_packet.decode())

def extract_keystream(enc_packet):
    known_json = json.dumps({'user': 'user', 'command': 'nop', 'token':'sdsd'}).encode()  #Random tokenn not gonne use anyway
    # Out of total data, first 8 bytes : nonce, next 4 bytes : checksum rest ciphertext (See code)
    ciphertext = enc_packet[12:]  # 0-11 bytes : nonce + checksum
    # The nonce value in the known_json is not used anywhere so we will just skip that
    # We just need to find keystream for 35 bytes

    keystream = []
    for i in range(35):
        keystream.append(ciphertext[i] ^ known_json[i])
    return keystream

def construct_payload(keystream, enc_packet):
    payload_skeleton = json.dumps({'user': 'root', 'command': 'flag'}).encode()
    enc_payload = []
    for i in range(len(payload_skeleton)):
        enc_payload.append(payload_skeleton[i] ^ keystream[i])
    enc_payload = bytes(enc_payload)
    nonce = enc_packet[:8]
    new_checksum = long_to_bytes(crc32(payload_skeleton))  #SOME PROBLEM HERE
    return nonce + new_checksum + enc_payload

def deploy_payload(payload):
    conn.recvuntil(b'> ')
    conn.sendline(b'R')
    conn.recvuntil(b': ')
    conn.sendline(payload.hex().encode())
    return conn.recvline().decode()

def main():
    enc_packet = get_encrypted_packet()
    keystream = extract_keystream(enc_packet)
    payload = construct_payload(keystream, enc_packet)
    flag = deploy_payload(payload)
    print("FLAG : ",flag)

if __name__ == "__main__":
    main()
```
### Solitude - Crypto

The given code is an implementation of [Solitaire Cipher](https://en.wikipedia.org/wiki/Solitaire_(cipher)). If we see the Wiki page it is clear that the cipher tends to repeat keystream bytes. We can exploit this by XORing together consecutive bytes in different flag encryptions and selecting the most common combinations.

How this Works? Suppose we have 1st byte of ciphertext C1 and 2nd byte C2. Since keystream tends to repeat at some point we will get the same keystream used in the original encryption.  
```
C1=F⊕K1
C2=F⊕K2
C1⊕C2=(F⊕K1)⊕(F⊕K2)
So, C1⊕C2=K1⊕K2
```

Now if we take 100,000 ciphertexts and store the XOR value of consecutive bytes, we will find that the most frequent value is going to be the C1⊕C2 value. (This is because for any other key that is not F, it will produce random values, but for F, it will uniformly produce the same value) Thus for each byte, we can get the byte used as key this way. Now we know the first character of flag is 'i' using that we can derive the second byte as

```
C1⊕C2=K1⊕K2
Now, K1⊕K2⊕K1 = K2
```

```python
from pwn import *

conn = process(["python","main.py"])

def oracle(cnum):
	conn.recvuntil(b'?')
	conn.sendline(str(cnum).encode())
	ciphertexts = []
	for i in range(cnum):
		ciphertexts.append(bytes.fromhex(conn.recvline().decode().strip()))
	return ciphertexts

def get_frequency_analysis():
	ciphertexts = oracle(100000)	# Get 100000 ciphertexts
	flag_length = len(ciphertexts[0])
	frequency = [{} for _ in range(flag_length - 1)]	# Get n-1 dictionaries so as to store frequency of difference of n bytes
	for i in ciphertexts:
		for j in range(flag_length - 1):
			xor_result = i[j+1] ^ i[j]
			if(xor_result not in frequency[j]):
				frequency[j][xor_result] = 1
			else:
				frequency[j][xor_result] += 1
	return frequency

def main():
	print("[-] Started Frequency Analysis")
	frequency = get_frequency_analysis()
	print("[✓] Finished Frequency Analysis")
	most_used_xor = []
	for dic in frequency:
		max_value = max(dic.values())
		for j in dic:
			if dic[j] == max_value:
				most_used_xor.append(j)

	flag = b'i'
	for i in range(len(most_used_xor)):
		flag += bytes([most_used_xor[i] ^ flag[i]])

	print("[✓] FLAG : ",flag)

if __name__ == "__main__":
	main()
```

### Lcasm - Crypto

Read the decompiled code, to understand that we need to put some shellcode in to get a shell.

The final value of x will be stored in the shellcode, since we can give a,c,m values, we just need to get a plaintext such that ciphertext becomes a shellcode.

We give initial state of LCG (x) and its parameters as input. Give parameters and state such that it "randomly" generated the required shellcode

Shellcode : `\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05`

Now we will assume a = 1. This makes things a lot simpler. Now we see that the code is taking 8 byte integers and performing LCG operation on it, and storing it in mmap. Now, remember that we can give the initial state. 

Once we give the initial state, after LCG is performed on it, we must get the integer equivalent of the first 8 bytes of the shellcode (Use pwn-u64 to convert bytes to 8 byte integer)

```
Suppose x1 is first 8 bytes of shellcode, x2 is next 8 bytes and x3 is last 8 bytes

We know that LCG(x1) = x2
Sinc a = 1
(x1 + c) %m = x2

Now assume x1 < x2 < m, in that case, we can eliminate the mod m in above equation. (We will have to find a shellcode where x1 will be less than x2. Here it is true)

x1 + c = x2
c = x2 - x1

Now LCG(x2) = x3. Now if x3 is laso greater than x2, we can repeat the above process. But that is not so in this case. So what we have to do is to reduce the value from x2 to x3 using mod m. We will have to choose the mod m carefully.

We do this by,
m = x2 + c - x3
(Since x3 = x2 + c. (x2 + c)%(x2 + c - x3) = x3)

Thats it pass in the parameters

```

```python
from pwn import u64
sc = b"\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
x1 = u64(sc[:8])
x2 = u64(sc[8:16])
x3 = u64(sc[16:24])
assert x1 < x2
c = x2 - x1
m = (x2 + c - x3)
assert m > 0
a = 1
x = x1 - c  # X IS INITIAL STATE
print('x = ',x)
print('a = ',a)
print('c = ',c)
print('m = ',m)
```

Now plug in the parameters you got into netcat server to get a shell.
