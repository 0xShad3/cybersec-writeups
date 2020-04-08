# fd

### Disclaimer!

I changed the original flag with the custom flag "Shad3 pwnned this", it's better to exploit it yourself,
than just copy it :P.

## Connecting to the server

That's the second challenge from pwnable.kr and it's an abstract hash collision.
By connecting through ssh to the server, 
```
ssh col@pwnable.kr -p2222
password:guest
```
we are been given 3 files as shown bellow 
```
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/collision$ ssh col@pwnable.kr -p2222
col@pwnable.kr's password: 
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
You have new mail.
col@pwnable:~$ ls
col  col.c  flag
```
## Analysing the source code

By analysing the source code bellow we get the idea of the challenge, let's explain briefly what the code
snippet does, it takes a passcode of 20 bytes length as the first argument and calculates sum of the integers
that these 20 bytes correspond to. Keep in mind one integer takes up space of 4 bytes, so that's 5 integers. Then, the script
compaires the sum of the 5 ints with the **hashcode** value (*0x21DD09EC*).


```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}

int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}
```

## Exploit

To exploit this we need to calculate 5 integers that have a sum of *0x21DD09EC*,append their hex values,
and give them as an argument. Keep in mind that just dividing the number by 5 we have a remainder of 4
So what we can do is just send 4 times the number 0x6c5cec8 (which is the value of the integer part of the division by 5) 
and append to that 0x6c5cec8 + 4 (0x6c5cecc). Keep in mind that it's an exploit in x86 system so we have to use little endian. 
In this case we can just do it with an one liner script:

```python
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/collision$ ./col `python -c "print '\xc8\xce\xc5\x06' * 4 + '\xcc\xce\xc5\x06'"`
Shad3 pwnned this!
```