import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',27027)
			#elf=ELF('')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def add(a,b,c):
			io.sendlineafter('Your choice:','1')
			io.sendlineafter("please tell me the desrcription's size.\n",str(a))
			io.sendafter('please tell me the desrcript of commodity.\n',b)
			io.sendafter(':\n',c)

		def show(a):
			io.sendlineafter('Your choice:','3')
			io.sendlineafter(': ',str(a))

		def delete(a):
			io.sendlineafter('Your choice:','2')
			io.sendlineafter(':',str(a))

		# add(0,0x20,'aaaa')
		# add(0,0x20,'bbbb')
		# add(0,0x20,'cccc')
		io.sendafter('Enter your name(1~32):','a'*32)
		
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue