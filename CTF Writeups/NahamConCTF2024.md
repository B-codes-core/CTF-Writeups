## Magic RSA - Crypto 

Simple small 'e' attack

```python
from gmpy2 import * 
list = [1061208, 1259712, 912673, 1092727, 1860867, 175616, 166375, 941192, 185193, 1030301, 941192, 185193, 912673, 140608, 175616, 185193, 140608, 941192, 970299, 1061208, 175616, 912673, 117649, 912673, 185193, 148877, 912673, 125000, 110592, 1030301, 132651, 132651, 1061208, 117649, 117649, 1061208, 166375, 1953125] 
ans = [iroot(i,3) for i in list] 
ans = [i[0] for i in ans]
ans = [chr(i) for i in ans] ''.join(ans)
```

Flag : flag{87b9eb9a4894bcf8a1a95a20e33f11f7}

## Encryption Server - Crypto 
Every time, a random 'N' is used to encrypt a message but e remains same. In the code, we find that e ranges from 500-1000. So I used a brute force script that checks for all e = 500 to 1000 whether `pow(m,e,n) = c`. 
Another simpler way of doing this is to encrypt 2. Since 2^e < n (n is very large) We can take log base 2 c to get the e value. Once we get the e value, we know that flag consists of hexadecimal. So we can bruteforce.
```python
from pwn import *

def find_e(n,c):
    for i in range(500,1000):
        if(pow(ord('f'),i,n)) == c:
            return i

def mapchar(n,e):
    numlist = list('0123456789abcdeflag{}')
    maplist = [pow(ord(i),e,n) for i in numlist]
    print(maplist,'\n\n\n\n\n\n')
    return maplist

def printflag(clist,maplist):
    numlist = '0123456789abcdeflag{}'
    flag = ''
    for i in clist:
        j = maplist.index(i)
        flag += numlist[i]
    print(flag)

conn = remote('challenge.nahamcon.com', 30463)
conn.recvuntil(b'>')
conn.sendline(b'1')
conn.recvuntil(b'>')
conn.sendline(b'f')
conn.recvuntil(b'>')
n = conn.recvline().decode()
n = n.replace('>','')
n = n.strip()
n = int(n)
conn.recvuntil(b'[')
c = conn.recvline().decode()
c = c.replace('>','')
c = c.replace('[','')
c = c.replace(']','')
c = c.strip()
c = int(c)
e = find_e(n,c)
print('e : ',e)
conn.recvuntil(b'>')
conn.sendline(b'2')
conn.recvuntil(b'>')
n = conn.recvline().decode()
n = n.replace('>','')
n = n.strip()
n = int(n)
maplist = mapchar(n,e)
conn.recvuntil(b'[')
clist = conn.recvline().decode()
clist = clist.replace('[','')
clist = clist.replace(']','')
clist = clist.replace(',','')
clist = list(clist.split(" "))
clist = [int(i) for i in clist]
print(clist)
printflag(clist,maplist)
```

## Rigged Lottery - Crypto 

This challenge is based on this paper : [https://pure.manchester.ac.uk/ws/portalfiles/portal/272368587/2307.12430v1.pdf](https://pure.manchester.ac.uk/ws/portalfiles/portal/272368587/2307.12430v1.pdf "https://pure.manchester.ac.uk/ws/portalfiles/portal/272368587/2307.12430v1.pdf") This paper was written for the UK lottery where number range is from 1 - 59. But the paper also mentions how to deduce the same for numbers upto 70 which is just what we need. Seeing Table 2 we need to use the finite geometry (E) 5 times (1-14, 14-28 and so on upto 70) When we do this we end up with the tickets given in the code
```python
from pwn import *
import random

context.log_level = "DEBUG"

tickets=[(1,2,3,4,9,10),(1,2,5,6,13,14),(1,2,7,8,11,12),(3,4,5,6,11,12),(3,4,7,8,13,14),(5,6,7,8,9,10),(9,10,11,12,13,14),
        (15,16,17,18,23,24),(15,16,19,20,27,28),(15,16,21,22,25,26),(17,18,19,20,25,26),(19,20,21,22,23,24),(17,18,21,22,27,28),(23,24,25,26,27,28),
        (29,30,31,32,37,38),(29,30,35,36,39,40),(29,30,33,34,41,42),(31,32,33,34,39,40),(33,34,35,36,37,38),(31,32,35,36,41,42),(37,38,39,40,41,42),
        (43,44,45,46,51,52),(43,44,49,50,53,54),(43,44,47,48,55,56),(45,46,47,48,53,54),(47,48,49,50,51,52),(45,46,49,50,55,56),(51,52,53,54,55,56),
        (57,58,59,60,65,66),(57,58,63,64,67,68),(57,58,61,62,69,70),(59,60,61,62,67,68),(59,60,63,64,69,70),(61,62,63,64,65,66),(65,66,67,68,69,70)]

conn = remote("challenge.nahamcon.com", 30904)
conn.recvuntil(b">>")
conn.sendline(str(len(tickets)).encode()) #No of tickets

for i in range(len(tickets)):
    for j in range(6):
        conn.recvuntil(b">>")
        conn.sendline(str(tickets[i][j]).encode())

try:
    while(True):
        print(conn.recvline())
except EOFError:
    print("Conversation Over")
    conn.close()
