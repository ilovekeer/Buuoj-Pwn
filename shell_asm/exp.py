import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_s_1')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_s_1')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28429)
			elf=ELF('./ciscn_s_1')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		


		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# success('libc_base:'+hex(libc_base))
		gdb.attach(io)
		pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue