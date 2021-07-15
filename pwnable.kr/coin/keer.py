import sys
from pwn import *
from ctypes import *
# binary='1'
# elf=ELF(binary)
# pdbg=pwn_debug(binary)
# pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
# pdbg.debug("2.23")
io=remote('pwnable.kr',9007)
context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			#io=pdbg.run("debug")
			io=pdbg.run("local")
			libc=pdbg.libc
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			# one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			# io=pdbg.run("remote")
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def pwn():
			io.recvuntil("N=")
			x=int(io.recvuntil(' ',drop=True))
			io.recvuntil("C=")
			c=int(io.recvuntil('\n',drop=True))
			x=int((x+1)/2)
			b=x
			a=0
			pay=str(0)
			for i in range(a+1,x):
				pay+=' '+str(i)
			io.sendline(pay)
			while True:
				data=io.recvline()
				if 'Correct!' in data:
					break
				if int(data)%10==0:
					x=int((x+1)/2)
					a=b
					b=b+x
					pay=str(a)
					for i in range(a+1,b):
						pay+=' '+str(i)
				if int(data)%10==9:
					x=int((x+1)/2)
					a=a
					b=b-x
					pay=str(a)
					for i in range(a+1,b):
						pay+=' '+str(i)
				io.sendline(pay)



		io.recvuntil("3 sec...")
		for i in range(100):
			pwn()
		




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