#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./afpd'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			# io=process(elfelf)
			io=process([elfelf],env={'LD_PRELOAD':'./lib/libatalk.so.18'})
			elf=ELF(elfelf)
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
		else :
			io=remote('node3.buuoj.cn',)
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		def add(a,b):
			io.sendlineafter('Your choice:','1')
			io.sendlineafter('size?>',str(a))
			io.sendafter('content:',b)

		def edit(a,b):
			io.sendlineafter('Your choice:','2')
			io.sendlineafter('Index:',str(a))
			io.sendafter('content:',b)

		def show(a):
			io.sendlineafter('Your choice:','3')
			io.sendlineafter('Index:',str(a))

		def delete(a):
			io.sendlineafter('Your choice:','4')
			io.sendlineafter('Index:',str(a))

		
		
		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# system_addr=libc.sym['system']

		# success('heap_base:'+hex(heap_base))
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue