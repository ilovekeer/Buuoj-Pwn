import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./car_market_asis_ctf_2016')
	elf=ELF('./car_market_asis_ctf_2016')
	#libc=ELF('')
else :
	io=remote('',)
	elf=ELF('./car_market_asis_ctf_2016')
	#libc=ELF('')

def show():
	io.sendlineafter('>\n','1')

def add_car(a,b):
	io.sendlineafter('>\n','2')
	io.sendlineafter('Enter car model\n',a)
	io.sendlineafter('price\n',str(b))

def remove_car(a):
	io.sendlineafter('>\n','3')
	io.sendlineafter('index\n',str(a))

def select_car(a):
	io.sendlineafter('>\n','4')
	io.sendlineafter('index\n',str(a))


gdb.attach(io)
pause()
io.interactive()