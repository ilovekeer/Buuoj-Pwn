import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('')
	elf=ELF('')
	libc=ELF('')
else :
	io=remote('',)
	elf=ELF('')
	libc=ELF('')


gdb.attach(io)
pause()
io.interactive()