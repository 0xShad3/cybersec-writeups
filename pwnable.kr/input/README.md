# flag

### Disclaimer!

I changed the original flag with the custom flag "Shad3 pwnned this", it's better to exploit it yourself,than just copy it :P.

My solution works locally if you want to run it on the server just transfer the script there on a 
/tmp folder and create a link to the "input" executable on the home directory.
## Introduction

This one is more of a programming task than a pwn one. That of course doesn't mean it's not important, to be fair this challenge could be characterised as the ABC of pwn. With that being said lets jump into it.

All that challenge is about is knowing how to give input to a program it's also clear from the challenge description. By connecting to the server through ssh we've been given three files as shown bellow, these are the executable binary, the C code and of course the flag.
```python
shad3@zeroday:~$ ssh input2@pwnable.kr -p2222
input2@pwnable.kr's password: 
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
input2@pwnable:~$ ls -la
total 44
drwxr-x---   5 root       input2  4096 Oct 23  2016 .
drwxr-xr-x 116 root       root    4096 Nov 12 21:34 ..
d---------   2 root       root    4096 Jun 30  2014 .bash_history
dr-xr-xr-x   2 root       root    4096 Aug 20  2014 .irssi
drwxr-xr-x   2 root       root    4096 Oct 23  2016 .pwntools-cache
-r--r-----   1 input2_pwn root      55 Jun 30  2014 flag
-r-sr-x---   1 input2_pwn input2 13250 Jun 30  2014 input
-rw-r--r--   1 root       root    1754 Jun 30  2014 input.c
input2@pwnable:~$
```


## Code Analysis

Let's start analysing the code we've been given.
```c
input2@pwnable:~$ cat input.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
	printf("Welcome to pwnable.kr\n");
	printf("Let's see if you know how to give input to program\n");
	printf("Just give me correct inputs then you will get the flag :)\n");

	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");	

	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");
	
	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");

	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");	

	// network
	int sd, cd;
	struct sockaddr_in saddr, caddr;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    		return 1;
	}
	listen(sd, 1);
	int c = sizeof(struct sockaddr_in);
	cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
	if(cd < 0){
		printf("accept error, tell admin\n");
		return 0;
	}
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");

	// here's your flag
	system("/bin/cat flag");	
	return 0;
}
```
We can understand that this binary is divided in 5 different stages each one is a different way to give input to the program, these are:
- As **argument(s)**
    It asks the 'A'th (that's 65 in decimal) argument out of the 100 that it needs to be "\x00" and the 'B'th (66th in decimal) to be "\x20\x0a\x0d"
- Through **STDIO**
    It wants to "give as an input through stdio "  "\x00\x0a\x00\xff" of course all of these characters are unprintable,that's fine we'll bypass this by writing a script, it also wants to read from STDERR.
- Through an **environment variable**
    It asks to set an environment variable with the name of "\xde\xad\xbe\xef" that has the value of "\xca\xfe\xba\xbe"
- Through a **file**
    It wants from us to make a file with the name of "\x0a" that has as a content the following null bytes "\x00\x00\x00\x00"
- Over Network through a **socket**
    It wants from us to connect at the port given as the 'C'th argument that's the 67th argument. That means that we can control the port that we need to connect. And send the "\xde\xad\xbe\xef" string there :). Then we'll hopefully get our flag


So lets code the solution to get our flag using pwntools <3 :)

Im not getting into details for each one of the stages.



```python
from pwn import *

# Preparing the arguments for first stage
argvs = []
for i in range(101):
    argvs.append("A")
    if (i == 0):
        argvs.append("./input")

    if (i == ord('A')):
        argvs.append("\x00")

    if (i == ord('B')):
        argvs.append("\x20\x0a\x0d")

    if (i == ord('C')):
        argvs.append(1337)    # This one is for the final stage


# Getting ready for stage 2
with open("./toSTDERR", 'w+') as stderror:
    stderror.write("\x00\x0a\x02\xff")
    stderror.seek(0)

# Getting ready for  Stage 3
envar = {"\xde\xad\xbe\xef": "\xca\xfe\xba\xbe"}


# Getting ready for stage 4

fd = ('./\x0a','w+')
fd.write('\x00\x00\x00\x00')
fd.close()

# Starting the process

p = process(executable='./input',argv=argvs,stderr=stderror,env=envar)
p.recvuntil('Stage 1 clear!\n')
p.send("\x00\x0a\x00\xff")
p.recvuntil('Stage 2 clear!\n')
p.recvuntil('Stage 3 clear!\n')
p.recvuntil('Stage 4 clear!\n')

# Setting up for the final stage
sock = remote('127.0.0.1',1337,typ=tcp)
sock.send("\xde\xad\xbe\xef")
sock.close()

p.recvuntil('Stage 5 clear!\n')
p.interactive()
```
By running the script above we'll get our flag :).

```bash
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/input$ python code.py
Stage 1 clear!
Stage 2 clear!
Stage 3 clear!
Stage 4 clear!
[+] Opening connection to 127.0.0.1 on port 1337: Done
[*] Closed connection to 127.0.0.1 port 1337
Stage 5 clear!
Shad3 pwnned this!
```
