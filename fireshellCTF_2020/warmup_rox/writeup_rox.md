#Overview

Warmup ROX (PPC)

The name of the challenge was a huge hint to me "ROX - XOR", that's what it came to my mind straight up
so as always that's what I was about to try first! :).

By connecting to the service using netcat it tells us that a lenngt(?) is 26, and it asks us for some input,
by sending some data it returns us gibberish, so my guess is that it's an XOR encryption the key's length is 26 bytes and the return value
is the encrypted data of our user input. 

```
shad3@zeroday:~/Desktop/CTF/fireshell/ppc$ nc 142.93.113.55 31087

                     +++     Fireshell CTF - ROX     +++

 [+] Length is 26. Type 'start' to start: start
 [+] 1 / 100 Input: aaaaaaaaaaaaaaaaaaaaaaaaaaa
			 Output: 'BPL9QL3.LUL
```

That tells us gives us 2 basic info: 
1) The key is **not bruteforceable** 
2) I control the **plaintext** and I have **access to the ciphertext** 
Based on my assumption I moved on, So how do we steal the key then?

Lets consider an example where we have a key length of one (key = 'A') and plaintext = '0x00'

Then the based on the XOR truth table :

We'll have the following "ciphertext"
```
PLAINTEXT   : 00000000
KEY 		: 01000001
=======================
CIPHERTEXT  : 01000001
```

**Hopefully you get the idea now :).**

##Pwn
So lets write a simple script to get our flag and check if our assumption is correct:

```
from pwn import *

conn = remote('142.93.113.55',31087)
conn.recvuntil('start:')
conn.send('start')

for i in range(100):
    conn.recvuntil('Input: ')
    conn.send('\x00' * 26)
    a = conn.recvline()
    print(a)


```

```
shad3@zeroday:~/Desktop/CTF/fireshell/ppc$ python xor.py 
[+] Opening connection to 142.93.113.55 on port 31087: Done
 [+] Output: F#{us1ng-X0r-is-ROx-4-l0t}

 [+] Output: F#{us1ng-X0r-is-ROx-4-l0t}

 [+] Output: F#{us1ng-X0r-is-ROx-4-l0t}

```