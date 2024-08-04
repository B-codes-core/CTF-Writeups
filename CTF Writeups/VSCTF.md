### Dream - Crypto
 
This question is about predicting the next random number by predicting the state of mersenne twister, which python uses to generate random numbers. To predict the state of the MT, we need to get 624 consecutive generated random numbers, and using that we can reverse the state of MT. But in our case the code is allowing us to get only 8 numbers. But there is a twist... Due to improper implementation of the code in the backend, each time i call netcat, and obtain first 8 random numbers, i am getting thee same numbers (but since in the code os.urandom(8) is used to set the seed each time code is called, this shouldn't theoretically happen). Now using this flaw, I obtained 624 consecutive numbers, by creating a connection, getting 8 numbers, closing again creating connection, getting next 8 numbers and so on

```python
from pwn import *
nums = []
for i in range(78):
        conn = remote("vsc.tf", 5001)
        a = []
        for i in range(i*8,i*8+8):
                a.append(str(i))
        a = ','.join(a)
        conn.recvuntil(b'>>>')
        conn.sendline(a.encode())
        for i in range(8):
                nums.append(int(conn.recvline().decode().strip()))
        conn.close()
print(nums)
```

Now I got 624 numbers, I used this code ([https://github.com/tna0y/Python-random-module-cracker/blob/master/randcrack/randcrack.py](https://github.com/tna0y/Python-random-module-cracker/blob/master/randcrack/randcrack.py "https://github.com/tna0y/Python-random-module-cracker/blob/master/randcrack/randcrack.py")) to predict the state of the MT by modifying thee code a little bit in main(). After the state is set, I call random.getrandbits(256) 2 times to get the key and nonce (Remember now we got the seed used in original code after predicting the state, so we will get same key and nonce as the original program). New main function after edit shown below.

```python
outputs = [] #Replace with the 624 numbers
for i in outputs:
        cracker.submit(i)
    print(cracker.predict_getrandbits(256))
    print(cracker.predict_getrandbits(256))
```
