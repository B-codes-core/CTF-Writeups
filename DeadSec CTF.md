### Flag Killer (Crypto)

Play around with the given function to see that there is a unique mapping between the input and output. Since possible inputs are from 000 - FFF, we can create a dictionary to map all outputs to the corresponding input, and then use the dictionary to get the flag.
```python
def FLAG_KILLER(value):
    index = 0
    temp = []
    output = 0
    while value > 0:
        temp.append(2 - (value % 4) if value % 2 != 0 else 0
        value = (value - temp[index])/2
        index += 1
    temp = temp[::-1]
    for index in range(len(temp)):
        output += temp[index] * 3 ** (len(temp) - index - 1)
    return output
enc = "0e98b103240e99c71e320dd330dd430de2629ce326a4a2b6b90cd201030926a090cfc5269f904f740cd1001c290cd10002900cd100ee59269a8269a026a4a2d05a269a82aa850d03a2b6b900883"
enc = [enc[i:i+5] for i in range(0,len(enc),5)]
fk = {}
for i in range(0xfff+1):
    fk['%05x' % int(FLAG_KILLER(i))] = hex(i)[2:].zfill(3)
dec = []
for i in enc[:-1]:
    dec.append(fk[i])
dec.append(fk[enc[-1]][1:])
pt = bytes.fromhex("".join(dec)).decode()
print(pt)
```