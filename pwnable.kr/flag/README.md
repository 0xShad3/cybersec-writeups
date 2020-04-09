# flag

### Disclaimer!

I changed the original flag with the custom flag "Shad3 pwnned this", it's better to exploit it yourself,
than just copy it :P.

## Background 

This is a reversing challenge from pwnable.kr, that introduces something pretty basic but important
especially for the CTF-players out there, UPX packing - unpacking.

### Enumeration

Executing file on the binary gives us some basic information about it,
```python
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/flag$ file flag 
flag: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=96ec4cc272aeb383bd9ed26c0d4ac0eb5db41b16, not stripped
``` 
That's a stripped and statically linked binary aka you cannot reverse this just by openning it in the disassembler hoping
to get some beautyfull pseudocode from a decompiler. 

**Disclaimer**: You can reverse this by applying some function signatures renaming variables etc. but this is pretty painfull and since its one of the first challenges, I'll leave that as our last choice.

Just by executing the binary we get the usefull information that the an array will allocated and the flag will get coppied there. 
```python
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/flag$ ./flag 
I will malloc() and strcpy the flag there. take it.
```


By running strings against it and hunting for long strings we get an important string that will help us a lot

```python
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/flag$ strings -15 flag 
'''' (0h''''HPX`
np!f@(Q[uIB(0Tc
FFFF|vpjFFFFd^XR
^0HMdZp)->? & 0+03
?../:deps/x86_64
?_OUTPU1YNAMIC_WEAK
_~SO/IEC 14652 i18n FDC
*+,-./0>3x6789:;<=>?
@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_
`abcdefghijklmnopqrstuvwxyz{|}~
ANSI_X3.4&968//T
 "9999$%&/999956799999:<DG9999HI_`
#6''''<dej''''k
 ''''!#$`''''abcd''''efgh''''ijkl''''mnop''''qrst''''uvwx''''yz{|''''}~
Q2R''''STUV''''WXYZ''''[\]^''''_
MNONNNNPRTUNNNNVWYZNNNN[\_`NNNNabcdNNNNefhi
 rrrr!"#$rrrr%&'(rrrr)*+,rrrr-./0rrrr1234rrrr5678rrrr9;<=rrrr>@ABrrrrCDFJrrrrKLMNrrrrOPRSrrrrTUVWrrrrXYZ[rrrr\]^_rrrr`abcrrrrdefgrrrrhijkrrrrlmnorrrrpqrsrrrrtuvwrrrrxyz{rrrr|}~
 !"9999#$%&9999'()*9999+,-.9999/012999934569999789:9999;<=>9999?@AB9999CDEF9999GHIJ9999KLMN9999OPQR9999STUV9999WXYZ9999[\]^9999_`ab9999cdef9999ghij9999klmn9999opqr9999stuv9999wxyz9999{|}~9999
'12Wr%W345%Wr%67x!Wr892
b'cdr%WrefgWr%Whij%Wr%klr%WrmnoWr%Wpqr%Wr%str%WruvwWr%Wxyz%Wr%ABr%WrCDEWr%WFGH%Wr%IJr%WrKLMWr%WNOP%Wr%QRr%WrSTUWr%WVWX%Wr%YZ
_r%W;k'MGEp%WTu
pchuilqesyuustuw
 $9999(/6>9999HQXa9999eimq9999uy}
&9223372036854775807L`
PROT_EXEC|PROT_WRITE failed.
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.08 Copyright (C) 1996-2011 the UPX Team. All Rights Reserved. $
GCC: (Ubuntu/Linaro 4.6.3-1u)#
ild-id$rela.plt
call_gmon_start
DEH_FRAME_BEGINf
_PRETTY_FUNCT0Na
C_>YPE/NUMERIC?
```

Check this out, it tells us how the binary got packed:

``` 
Info: This file is packed with the UPX executable packer http://upx.sf.net 
``` 
More info for UPX compression, on the link of the string ( http://upx.sf.net ).
To unpack it we just have to install UPX
```
sudo apt-get install upx
```
and run **upx -d** against it.

```python
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/flag$ upx -d flag 
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2017
UPX 3.94        Markus Oberhumer, Laszlo Molnar & John Reiser   May 12th 2017

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    883745 <-    335288   37.94%   linux/amd64   flag

Unpacked 1 file.
```
## Solution
There we go, now we have an unpacked binary file we can work with.
I'm not going to even bother, openning ghidra since we know that it executes a malloc and strcpy()
the flag. So if we just set a breakpoint in gdb just after the flag is loaded on the memmory we can just look at register XREF values of the registers and find it there in plaintext (in this situation peda shows that for us automatically). 


```
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/flag$ gdb 
GNU gdb (Ubuntu 8.1-0ubuntu3.2) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word".
gdb-peda$ set disassembly-flavor intel 
gdb-peda$ disassemble main
No symbol table is loaded.  Use the "file" command.
gdb-peda$ file flag 
Reading symbols from flag...(no debugging symbols found)...done.
gdb-peda$ disassemble main
gdb-peda$ disassemble main
Dump of assembler code for function main:
   0x0000000000401164 <+0>:     push   rbp
   0x0000000000401165 <+1>:     mov    rbp,rsp
   0x0000000000401168 <+4>:     sub    rsp,0x10
   0x000000000040116c <+8>:     mov    edi,0x496658
   0x0000000000401171 <+13>:    call   0x402080 <puts>
   0x0000000000401176 <+18>:    mov    edi,0x64
   0x000000000040117b <+23>:    call   0x4099d0 <malloc>
   0x0000000000401180 <+28>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000401184 <+32>:    mov    rdx,QWORD PTR [rip+0x2c0ee5]        # 0x6c2070 <flag>
   0x000000000040118b <+39>:    mov    rax,QWORD PTR [rbp-0x8]
=> 0x000000000040118f <+43>:    mov    rsi,rdx
   0x0000000000401192 <+46>:    mov    rdi,rax
   0x0000000000401195 <+49>:    call   0x400320
   0x000000000040119a <+54>:    mov    eax,0x0
   0x000000000040119f <+59>:    leave  
   0x00000000004011a0 <+60>:    ret    
End of assembler dump.
```
Setting the breakpoint :
```
gdb-peda$ break *0x000000000040118b
Breakpoint 1 at 0x40118b
```
And then as said all we have to do is just to execute the binary.

```
[----------------------------------registers-----------------------------------]
RAX: 0x6c96b0 --> 0x0 
RBX: 0x401ae0 (<__libc_csu_fini>:       push   rbx)
RCX: 0x8 
RDX: 0x496628 ("Shad3 Pwnned this!")
RSI: 0x0 
RDI: 0x4 
RBP: 0x7fffffffdcf0 --> 0x0 
RSP: 0x7fffffffdce0 --> 0x401a50 (<__libc_csu_init>:    push   r14)
RIP: 0x40118b (<main+39>:       mov    rax,QWORD PTR [rbp-0x8])
R8 : 0x1 
R9 : 0x3 
R10: 0x22 ('"')
R11: 0x0 
R12: 0x401a50 (<__libc_csu_init>:       push   r14)
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40117b <main+23>:  call   0x4099d0 <malloc>
   0x401180 <main+28>:  mov    QWORD PTR [rbp-0x8],rax
   0x401184 <main+32>:  mov    rdx,QWORD PTR [rip+0x2c0ee5]        # 0x6c2070 <flag>
=> 0x40118b <main+39>:  mov    rax,QWORD PTR [rbp-0x8]
   0x40118f <main+43>:  mov    rsi,rdx
   0x401192 <main+46>:  mov    rdi,rax
   0x401195 <main+49>:  call   0x400320
   0x40119a <main+54>:  mov    eax,0x0
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdce0 --> 0x401a50 (<__libc_csu_init>:   push   r14)
0008| 0x7fffffffdce8 --> 0x6c96b0 --> 0x0 
0016| 0x7fffffffdcf0 --> 0x0 
0024| 0x7fffffffdcf8 --> 0x401344 (<__libc_start_main+404>:     mov    edi,eax)
0032| 0x7fffffffdd00 --> 0x0 
0040| 0x7fffffffdd08 --> 0x100000000 
0048| 0x7fffffffdd10 --> 0x7fffffffdde8 --> 0x7fffffffe18e ("/home/shad3/Desktop/Security/CTF/pwnable.kr/flag/flag")
0056| 0x7fffffffdd18 --> 0x401164 (<main>:      push   rbp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x000000000040118b in main ()
```
As you can see the **fake flag** gets loaded on the RDX register!.