# leg

This challenge is a bit different than the others that we've seen before. It's impossible to compile, and run the source code of the given program on an x86 system since that is written for ARM architecture. But what we can do is that we can disassemble it and do some static analysis on that hoping to give the correct input.

### Disclaimer
I changed the original flag with the custom flag "Shad3 pwnned this", it's better to exploit it yourself,
than just copy it :P.

## Source Code Analysis
By analysing the source code bellow, we get the main idea of the challenge we just have to give one correct input that has be equal to the sum of the return values of the three key functions. Tha will give us the flag.

```python
#include <stdio.h>
#include <fcntl.h>
int key1(){
	asm("mov r3, pc\n");
}
int key2(){
	asm(
	"push	{r6}\n"
	"add	r6, pc, $1\n"
	"bx	r6\n"
	".code   16\n"
	"mov	r3, pc\n"
	"add	r3, $0x4\n"
	"push	{r3}\n"
	"pop	{pc}\n"
	".code	32\n"
	"pop	{r6}\n"
	);
}
int key3(){
	asm("mov r3, lr\n");
}
int main(){
	int key=0;
	printf("Daddy has very strong arm! : ");
	scanf("%d", &key);
	if( (key1()+key2()+key3()) == key ){
		printf("Congratz!\n");
		int fd = open("flag", O_RDONLY);
		char buf[100];
		int r = read(fd, buf, 100);
		write(0, buf, r);
	}
	else{
		printf("I have strong leg :P\n");
	}
	return 0;
}
```

Let's take a look at the leg.asm file which contains the disassembled functions,these functions will help us figure out the value that we need based upon some basic features of the ARM architecture.

### Key 1

By taking a look in the C code we see that we have to get the value of the programm counter PC (same as Instruction Pointer in x86) plus 8 bytes.
```c
int key1(){
	asm("mov r3, pc\n");
}
```
From the assembler dump below we can easily figure out that this has to be ``0x00008ce4``.
```bash
(gdb) disass key1
Dump of assembler code for function key1:
   0x00008cd4 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cd8 <+4>:	add	r11, sp, #0
   0x00008cdc <+8>:	mov	r3, pc
   0x00008ce0 <+12>:	mov	r0, r3
   0x00008ce4 <+16>:	sub	sp, r11, #0
   0x00008ce8 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008cec <+24>:	bx	lr
```
### Key 2
We are now on Thumb mode (more info about the modes on the references), similarly for the key2 function.
By looking on the assembler dump the value we need is on the push_r3 instruction + 4 bytes instead of 8 since now we are on 16-bit mode. The value that the **key2()** will return has to be ``0x00008d0c``
```bash
(gdb) disass key2
Dump of assembler code for function key2:
   0x00008cf0 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008cf4 <+4>:	add	r11, sp, #0
   0x00008cf8 <+8>:	push	{r6}		; (str r6, [sp, #-4]!)
   0x00008cfc <+12>:	add	r6, pc, #1
   0x00008d00 <+16>:	bx	r6
   0x00008d04 <+20>:	mov	r3, pc
   0x00008d06 <+22>:	adds	r3, #4
   0x00008d08 <+24>:	push	{r3}
   0x00008d0a <+26>:	pop	{pc}
   0x00008d0c <+28>:	pop	{r6}		; (ldr r6, [sp], #4)
   0x00008d10 <+32>:	mov	r0, r3
   0x00008d14 <+36>:	sub	sp, r11, #0
   0x00008d18 <+40>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d1c <+44>:	bx	lr
End of assembler dump.
```


### Key 3 
Finally for the last function from the assembler dump bellow we see that lr gets moved on R3, LR in ARM is the link register which stores the return address of the function. With that being said we figure out that **key3()** has to return the value of ``0x00008d80``. 
```bash
(gdb) disass key3
Dump of assembler code for function key3:
   0x00008d20 <+0>:	push	{r11}		; (str r11, [sp, #-4]!)
   0x00008d24 <+4>:	add	r11, sp, #0
   0x00008d28 <+8>:	mov	r3, lr
   0x00008d2c <+12>:	mov	r0, r3
   0x00008d30 <+16>:	sub	sp, r11, #0
   0x00008d34 <+20>:	pop	{r11}		; (ldr r11, [sp], #4)
   0x00008d38 <+24>:	bx	lr
```

## Solution 
By addinng up all the values we collected and getting the decimal value out of the result, will give us the desired input that will get us the flag.

```python
shad3@zeroday:~/Desktop/Security/CTF/pwnable.kr/leg$ python
Python 2.7.17 (default, Nov  7 2019, 10:07:09) 
[GCC 7.4.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x00008ce4 + 0x00008d0c + 0x00008d80
108400
```
Getting the flag!!!

```
/ $ ./leg 
Daddy has very strong arm! : 108400 
Congratz!
Shad3 pwnned this
```